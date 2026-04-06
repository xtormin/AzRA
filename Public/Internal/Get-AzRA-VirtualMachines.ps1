# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-VirtualMachines {
    <#
    .SYNOPSIS
    Enumerates Azure Virtual Machines and SQL Server VMs, auditing them for security
    misconfigurations and network exposure across all accessible subscriptions.

    .DESCRIPTION
    Iterates across all accessible subscriptions (or a specific one), lists all Compute VMs
    and SQL VMs, and evaluates each against security checks organized by severity:

      Critical:     Public IPs, open RDP/SSH/WinRM/SQL ports, dangerous extensions
                    (CustomScript, RunCommand), SQL public connectivity / mixed auth
      High:         OS/data disk encryption (no CMK), encryption at host, Secure Boot,
                    vTPM, AAD login extension missing, no managed identity, boot diagnostics
                    enabled, SQL EOL version, no SQL backup, MMA agent installed
      Informational: No tags, Spot instances, ephemeral OS disk, single NIC

    For each VM the function resolves the full VM → NIC → Public IP → NSG chain to detect
    actual internet-facing exposure and open inbound ports.

    SQL VMs (Microsoft.SqlVirtualMachine provider) are pre-indexed and correlated to their
    underlying Compute VM by ARM resource ID, adding SQL-specific checks to the same object.

    When -IncludeInstanceView is specified, an additional API call per VM retrieves the
    instance view for power state and OS details. This is disabled by default due to the
    significant extra API load at scale.

    Required permissions:
      Microsoft.Compute/virtualMachines/read
      Microsoft.Compute/virtualMachines/extensions/read
      Microsoft.SqlVirtualMachine/sqlVirtualMachines/read
      Microsoft.Network/networkInterfaces/read
      Microsoft.Network/publicIPAddresses/read
      Microsoft.Network/networkSecurityGroups/read

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription by ID. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where all output is saved. Raw JSON dumps are saved under:
      <OutputPath>\VirtualMachinesRawDump\<SubscriptionName>\<VmName>\vm.json
      <OutputPath>\VirtualMachinesRawDump\<SubscriptionName>\<VmName>\extensions.json
      <OutputPath>\VirtualMachinesRawDump\<SubscriptionName>\<VmName>\network.json
      <OutputPath>\VirtualMachinesRawDump\<SubscriptionName>\<VmName>\sqlvm.json  (if SQL VM)
    CSV report is saved as:
      <OutputPath>\AzRA-VirtualMachines_<yyyyMMdd-HHmm>.csv

    .PARAMETER IncludeInstanceView
    If specified, makes an additional API call per VM to retrieve the instance view,
    populating PowerState, ProvisioningState, and OS details from the live instance.
    Disabled by default — adds one API call per VM which is significant at scale.

    .PARAMETER MaxRetries
    Maximum retry attempts on throttling (HTTP 429) or transient errors (5xx).
    Must be between 1 and 10. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries (multiplied by attempt number).
    Must be between 1 and 60. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-VirtualMachines -AccessToken $token
    Enumerates all VMs and returns security metadata to the pipeline.

    .EXAMPLE
    Get-AzRA-VirtualMachines -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Scans a single subscription.

    .EXAMPLE
    Get-AzRA-VirtualMachines -AccessToken $token -OutputPath 'C:\Audit'
    Enumerates all VMs, dumps JSON definitions and exports a metadata CSV.

    .EXAMPLE
    Get-AzRA-VirtualMachines -AccessToken $token -IncludeInstanceView -OutputPath 'C:\Audit'
    Full audit including power state and OS version data.

    .EXAMPLE
    Get-AzRA-VirtualMachines -AccessToken $token |
        Where-Object { $_.RdpExposed -or $_.SshExposed -or $_.CustomScriptExtension } |
        Select-Object VmName, ResourceGroup, PublicIpAddresses, OpenInboundPorts
    Returns only VMs with critical internet exposure or dangerous extensions.

    .EXAMPLE
    Get-AzRA-VirtualMachines -AccessToken $token |
        Where-Object { $_.IsSqlVm -and ($_.SqlPublicConnectivity -or $_.SqlMixedAuthEnabled) } |
        Select-Object VmName, SqlImageSku, SqlConnectivity, PublicIpAddresses
    Returns SQL VMs with dangerous connectivity or authentication settings.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Each object contains identity fields, boolean security check results, network exposure
    details, installed extensions, and optional SQL VM metadata.

    .LINK
    https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines
    https://learn.microsoft.com/en-us/rest/api/sqlvm/sql-virtual-machines
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeInstanceView,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySec = 5
    )

    # ── Private helpers ───────────────────────────────────────────────────────

    function Get-RgFromId {
        param([string]$Id)
        if ($Id -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
        return $null
    }

    function Get-NameFromId {
        param([string]$Id)
        return $Id.Split('/')[-1]
    }

    function Get-ComputeApiHeaders {
        return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    }

    # Evaluates whether any NSG rule opens the given ports to the internet
    function Test-NsgPortOpen {
        param(
            [object[]]$Rules,
            [int[]]$Ports,
            [ref]$OpenPorts
        )
        $found = $false
        foreach ($rule in $Rules) {
            $p = $rule.properties
            if ($p.direction -ne 'Inbound') { continue }
            if ($p.access -ne 'Allow') { continue }
            $src = [string]$p.sourceAddressPrefix
            if ($src -notin @('*', '0.0.0.0/0', 'Internet', '::/0', 'Any')) { continue }

            # Collect all port ranges to check
            $portRanges = [System.Collections.Generic.List[string]]::new()
            if ($p.destinationPortRange)  { $portRanges.Add($p.destinationPortRange) }
            if ($p.destinationPortRanges) { foreach ($pr in $p.destinationPortRanges) { $portRanges.Add($pr) } }

            foreach ($portRange in $portRanges) {
                if (-not $portRange) { continue }
                foreach ($port in $Ports) {
                    $match = $false
                    if ($portRange -eq '*' -or $portRange -eq 'Any') { $match = $true }
                    elseif ($portRange -eq "$port") { $match = $true }
                    elseif ($portRange -match '^(\d+)-(\d+)$') {
                        if ($port -ge [int]$Matches[1] -and $port -le [int]$Matches[2]) { $match = $true }
                    }
                    if ($match) {
                        $found = $true
                        if ($OpenPorts -and $OpenPorts.Value -notcontains "$port") {
                            $OpenPorts.Value += "$port"
                        }
                    }
                }
            }
        }
        return $found
    }

    # ── Initialization ────────────────────────────────────────────────────────

    $allVms    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot  = $null

    # Prepare output directory (fail fast)
    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
            $dumpRoot = Join-Path $OutputPath 'VirtualMachinesRawDump'
            if (-not (Test-Path $dumpRoot)) {
                New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null
            }
        }
        catch {
            throw "Cannot create output directory '$OutputPath': $_"
        }
    }

    # ── Resolve subscriptions ─────────────────────────────────────────────────

    if ($SubscriptionId) {
        $subs = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$SubscriptionId`?api-version=2022-12-01" `
            -AccessToken $AccessToken -Method GET
        if (-not $subs) { throw "Subscription not found: $SubscriptionId" }
        $subs = @($subs)
    }
    else {
        $subs = Invoke-AzRARequest `
            -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' `
            -AccessToken $AccessToken -Method GET -EnablePagination
    }

    Write-Verbose "Subscriptions to scan: $($subs.Count)"

    # ── Main loop ─────────────────────────────────────────────────────────────

    foreach ($sub in $subs) {
        $subId   = $sub.subscriptionId
        $subName = $sub.displayName
        Write-Verbose "Scanning subscription: $subName ($subId)"

        # ── Pre-load SQL VM index (one call per subscription) ─────────────────
        # Maps lowercase Compute VM ARM ID → SQL VM object
        $sqlVmIndex = @{}
        try {
            $sqlVms = Invoke-AzRARequest `
                -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.SqlVirtualMachine/sqlVirtualMachines?api-version=2023-10-01" `
                -AccessToken $AccessToken -Method GET -EnablePagination

            if ($sqlVms) {
                foreach ($sqlVm in $sqlVms) {
                    if ($sqlVm.properties.virtualMachineResourceId) {
                        $key = $sqlVm.properties.virtualMachineResourceId.ToLower()
                        $sqlVmIndex[$key] = $sqlVm
                    }
                }
                Write-Verbose "  SQL VMs indexed: $($sqlVmIndex.Count)"
            }
        }
        catch {
            Write-Warning "  Could not enumerate SQL VMs in $subName`: $_"
        }

        # ── List Compute VMs ──────────────────────────────────────────────────
        $vms = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $vms) {
            Write-Verbose "  No Virtual Machines found in $subName"
            continue
        }

        Write-Verbose "  Virtual Machines found: $($vms.Count)"

        foreach ($vm in $vms) {
            $vmName = $vm.name
            $rgName = Get-RgFromId -Id $vm.id

            if (-not $rgName) {
                Write-Warning "  Could not extract Resource Group for VM '$vmName'"
                continue
            }

            Write-Verbose "  Processing: $vmName ($rgName)"

            $props = $vm.properties

            # ── Extensions ───────────────────────────────────────────────────
            $extensions = $null
            try {
                $extensions = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Compute/virtualMachines/$vmName/extensions?api-version=2024-07-01" `
                    -AccessToken $AccessToken -Method GET -EnablePagination
            }
            catch {
                Write-Warning "  Could not enumerate extensions for '$vmName': $_"
            }

            $extensionTypes = [System.Collections.Generic.List[string]]::new()
            if ($extensions) {
                foreach ($ext in $extensions) {
                    $extType = if ($ext.properties.type) { $ext.properties.type } else { $ext.type }
                    if ($extType) { $extensionTypes.Add($extType) }
                }
            }

            # ── Instance View (optional) ──────────────────────────────────────
            $instanceView = $null
            $powerState   = $null
            $osName       = $null
            if ($IncludeInstanceView) {
                try {
                    $instanceView = Invoke-AzRARequest `
                        -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Compute/virtualMachines/$vmName/instanceView?api-version=2024-07-01" `
                        -AccessToken $AccessToken -Method GET
                    if ($instanceView.statuses) {
                        foreach ($status in $instanceView.statuses) {
                            if ($status.code -match '^PowerState/') {
                                $powerState = $status.displayStatus
                            }
                        }
                    }
                    $osName = $instanceView.osName
                }
                catch {
                    Write-Warning "  Could not retrieve instance view for '$vmName': $_"
                }
            }

            # ── Network: NIC → Public IP → NSG chain ─────────────────────────
            $publicIpList   = [System.Collections.Generic.List[string]]::new()
            $privateIpList  = [System.Collections.Generic.List[string]]::new()
            $nsgRulesAll    = [System.Collections.Generic.List[object]]::new()
            $networkObjects = [System.Collections.Generic.List[object]]::new()
            $nicCount       = 0

            $nicRefs = $vm.properties.networkProfile.networkInterfaces
            if ($nicRefs) {
                $nicCount = @($nicRefs).Count
                foreach ($nicRef in $nicRefs) {
                    $nicId = $nicRef.id
                    if (-not $nicId) { continue }

                    try {
                        $nic = Invoke-AzWithRetry `
                            -OperationName "GET NIC: $(Get-NameFromId $nicId)" `
                            -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec `
                            -ScriptBlock {
                                Invoke-RestMethod `
                                    -Uri "https://management.azure.com$nicId`?api-version=2024-05-01" `
                                    -Headers (Get-ComputeApiHeaders) `
                                    -Method GET -ErrorAction Stop
                            }

                        $networkObjects.Add($nic)

                        # Collect IPs
                        if ($nic.properties.ipConfigurations) {
                            foreach ($ipConfig in $nic.properties.ipConfigurations) {
                                $privateIp = $ipConfig.properties.privateIPAddress
                                if ($privateIp) { $privateIpList.Add($privateIp) }

                                # Follow public IP reference
                                $pipId = $ipConfig.properties.publicIPAddress.id
                                if ($pipId) {
                                    try {
                                        $pip = Invoke-AzWithRetry `
                                            -OperationName "GET PublicIP: $(Get-NameFromId $pipId)" `
                                            -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec `
                                            -ScriptBlock {
                                                Invoke-RestMethod `
                                                    -Uri "https://management.azure.com$pipId`?api-version=2024-05-01" `
                                                    -Headers (Get-ComputeApiHeaders) `
                                                    -Method GET -ErrorAction Stop
                                            }
                                        $ipAddr = $pip.properties.ipAddress
                                        if ($ipAddr) { $publicIpList.Add($ipAddr) }
                                    }
                                    catch {
                                        Write-Warning "  Could not resolve Public IP for '$vmName': $_"
                                        $publicIpList.Add('(unresolved)')
                                    }
                                }
                            }
                        }

                        # Collect NSG rules
                        $nsgId = $nic.properties.networkSecurityGroup.id
                        if ($nsgId) {
                            try {
                                $nsgRules = Invoke-AzWithRetry `
                                    -OperationName "GET NSG rules: $(Get-NameFromId $nsgId)" `
                                    -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec `
                                    -ScriptBlock {
                                        Invoke-RestMethod `
                                            -Uri "https://management.azure.com$nsgId/securityRules?api-version=2024-05-01" `
                                            -Headers (Get-ComputeApiHeaders) `
                                            -Method GET -ErrorAction Stop
                                    }
                                if ($nsgRules.value) {
                                    foreach ($r in $nsgRules.value) { $nsgRulesAll.Add($r) }
                                }
                            }
                            catch {
                                Write-Warning "  Could not retrieve NSG rules for '$vmName': $_"
                            }
                        }
                    }
                    catch {
                        Write-Warning "  Could not retrieve NIC '$nicId' for '$vmName': $_"
                    }
                }
            }

            # ── Security checks ───────────────────────────────────────────────

            $hasPublicIp     = ($publicIpList.Count -gt 0)
            $nsgRulesArray   = $nsgRulesAll.ToArray()
            $openPortsList   = [System.Collections.Generic.List[string]]::new()
            $openPortsRef    = [ref]($openPortsList -as [string[]])

            # Only evaluate port exposure if there's a public IP AND NSG rules were retrieved
            $rdpExposed  = $false
            $sshExposed  = $false
            $winRmExposed= $false
            $sqlPortExp  = $false

            if ($hasPublicIp -and $nsgRulesArray.Count -gt 0) {
                $openPortsArr = @()
                $openRef = [ref]$openPortsArr
                $rdpExposed   = Test-NsgPortOpen -Rules $nsgRulesArray -Ports @(3389) -OpenPorts $openRef
                $openPortsArr = $openRef.Value
                $sshOpen = Test-NsgPortOpen -Rules $nsgRulesArray -Ports @(22) -OpenPorts ([ref]$openPortsArr)
                $sshExposed = $sshOpen
                $openPortsArr = $openRef.Value
                Test-NsgPortOpen -Rules $nsgRulesArray -Ports @(5985, 5986) -OpenPorts ([ref]$openPortsArr) | Out-Null
                $winRmExposed = ($openPortsArr -contains '5985' -or $openPortsArr -contains '5986')
                Test-NsgPortOpen -Rules $nsgRulesArray -Ports @(1433) -OpenPorts ([ref]$openPortsArr) | Out-Null
                $sqlPortExp = ($openPortsArr -contains '1433')
                $openPortsList = [System.Collections.Generic.List[string]]($openPortsArr | Where-Object { $_ })
            }

            # Extensions checks
            $extTypesArr            = $extensionTypes.ToArray()
            $customScriptExt        = ($extTypesArr -match 'CustomScriptExtension|CustomScript') -as [bool]
            $runCommandExt          = ($extTypesArr -match 'RunCommandWindows|RunCommandLinux') -as [bool]
            $aadLoginNotConfigured  = -not ($extTypesArr -match 'AADLoginForWindows|AADLoginForLinux')
            $mmaInstalled           = ($extTypesArr -match 'MicrosoftMonitoringAgent|OmsAgentForLinux') -as [bool]

            # Disk encryption (absence of CMK)
            $osDiskNotEncrypted = ($null -eq $props.storageProfile.osDisk.managedDisk.diskEncryptionSet) -and
                                  ($props.storageProfile.osDisk.encryptionSettings.enabled -ne $true)

            $dataDisksNotEncrypted = $false
            if ($props.storageProfile.dataDisks) {
                foreach ($disk in $props.storageProfile.dataDisks) {
                    if ($null -eq $disk.managedDisk.diskEncryptionSet -and
                        $disk.encryptionSettings.enabled -ne $true) {
                        $dataDisksNotEncrypted = $true
                        break
                    }
                }
            }

            $encAtHostDisabled   = ($props.securityProfile.encryptionAtHost -ne $true)
            $secureBootDisabled  = ($props.securityProfile.securityType -ne 'TrustedLaunch') -or
                                   ($props.securityProfile.uefiSettings.secureBootEnabled -ne $true)
            $vtpmDisabled        = ($props.securityProfile.uefiSettings.vTpmEnabled -ne $true)

            # Managed identity
            $identityType        = [string]$vm.identity.type
            $noManagedIdentity   = ($identityType -in @('', 'None') -or -not $vm.identity)

            # Boot diagnostics
            $bootDiagEnabled     = ($props.diagnosticsProfile.bootDiagnostics.enabled -eq $true)

            # Informational
            $noTags              = (-not $vm.tags -or ($vm.tags | Get-Member -MemberType NoteProperty | Measure-Object).Count -eq 0)
            $isSpot              = ($props.priority -eq 'Spot')
            $ephemeralOs         = ($props.storageProfile.osDisk.diffDiskSettings.option -eq 'Local')
            $singleNic           = ($nicCount -le 1)

            # ── SQL VM correlation ────────────────────────────────────────────
            $sqlVm = $sqlVmIndex[$vm.id.ToLower()]
            $isSqlVm = ($null -ne $sqlVm)

            $sqlMixedAuth      = $false
            $sqlPublicConn     = $false
            $sqlEolVersion     = $false
            $sqlNoBackup       = $false
            $sqlImageSku       = $null
            $sqlLicenseType    = $null
            $sqlConnectivity   = $null
            $sqlMgmtMode       = $null

            if ($isSqlVm) {
                $sp = $sqlVm.properties
                $sqlImageSku     = $sp.sqlImageSku
                $sqlLicenseType  = $sp.sqlServerLicenseType
                $sqlConnectivity = $sp.sqlConnectivity
                $sqlMgmtMode     = $sp.sqlManagement

                $sqlPublicConn   = ($sqlConnectivity -eq 'PUBLIC')
                # Mixed auth: SQL auth update settings present = SQL auth was configured
                $sqlMixedAuth    = ($null -ne $sp.sqlConnectivityUpdateSettings.sqlAuthUpdateUserName -or
                                    $sqlPublicConn)
                $sqlEolVersion   = ($sqlImageSku -match '2008|2012|2014')
                $sqlNoBackup     = ($sp.autoBackupSettings.enable -ne $true)
            }

            # ── Raw dump ──────────────────────────────────────────────────────
            $rawFilePath = $null
            if ($dumpRoot) {
                $safeSubName = $subName  -replace '[^a-zA-Z0-9_\-]', '_'
                $safeVmName  = $vmName   -replace '[^a-zA-Z0-9_\-]', '_'
                $vmDumpDir   = Join-Path (Join-Path $dumpRoot $safeSubName) $safeVmName

                if (-not (Test-Path $vmDumpDir)) {
                    try {
                        New-Item -ItemType Directory -Force -Path $vmDumpDir -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Warning "  Could not create dump directory '$vmDumpDir': $_"
                    }
                }

                if (Test-Path $vmDumpDir) {
                    # vm.json
                    try {
                        $vm | ConvertTo-Json -Depth 20 |
                            Set-Content -Path (Join-Path $vmDumpDir 'vm.json') -Encoding UTF8 -ErrorAction Stop
                    }
                    catch { Write-Warning "  Could not write vm.json for '$vmName': $_" }

                    # extensions.json
                    if ($extensions) {
                        try {
                            $extensions | ConvertTo-Json -Depth 10 |
                                Set-Content -Path (Join-Path $vmDumpDir 'extensions.json') -Encoding UTF8 -ErrorAction Stop
                        }
                        catch { Write-Warning "  Could not write extensions.json for '$vmName': $_" }
                    }

                    # network.json (serialized NICs + public IPs)
                    if ($networkObjects.Count -gt 0) {
                        try {
                            $networkObjects.ToArray() | ConvertTo-Json -Depth 15 |
                                Set-Content -Path (Join-Path $vmDumpDir 'network.json') -Encoding UTF8 -ErrorAction Stop
                        }
                        catch { Write-Warning "  Could not write network.json for '$vmName': $_" }
                    }

                    # sqlvm.json
                    if ($isSqlVm) {
                        try {
                            $sqlVm | ConvertTo-Json -Depth 10 |
                                Set-Content -Path (Join-Path $vmDumpDir 'sqlvm.json') -Encoding UTF8 -ErrorAction Stop
                        }
                        catch { Write-Warning "  Could not write sqlvm.json for '$vmName': $_" }
                    }

                    $rawFilePath = $vmDumpDir
                    Write-Verbose "  Dumped: $vmDumpDir"
                }
            }

            # ── Build pipeline object ─────────────────────────────────────────

            $obj = [PSCustomObject]@{
                # Identity
                SubscriptionId      = $subId
                SubscriptionName    = $subName
                ResourceGroup       = $rgName
                VmName              = $vmName
                VmId                = $vm.id
                Location            = $vm.location
                OsType              = $props.storageProfile.osDisk.osType
                VmSize              = $props.hardwareProfile.vmSize
                OsImagePublisher    = $props.storageProfile.imageReference.publisher
                OsImageOffer        = $props.storageProfile.imageReference.offer
                OsImageSku          = $props.storageProfile.imageReference.sku
                PowerState          = $powerState
                OsName              = $osName
                ProvisioningState   = $props.provisioningState

                # Critical checks (bool)
                HasPublicIp              = $hasPublicIp
                RdpExposed               = $rdpExposed
                SshExposed               = $sshExposed
                WinRmExposed             = $winRmExposed
                SqlPortExposed           = $sqlPortExp
                CustomScriptExtension    = $customScriptExt
                RunCommandExtension      = $runCommandExt
                SqlMixedAuthEnabled      = $sqlMixedAuth
                SqlPublicConnectivity    = $sqlPublicConn

                # High checks (bool)
                OsDiskNotEncrypted       = $osDiskNotEncrypted
                DataDiskNotEncrypted     = $dataDisksNotEncrypted
                EncryptionAtHostDisabled = $encAtHostDisabled
                SecureBootDisabled       = $secureBootDisabled
                VtpmDisabled             = $vtpmDisabled
                AadLoginNotConfigured    = $aadLoginNotConfigured
                NoManagedIdentity        = $noManagedIdentity
                BootDiagnosticsEnabled   = $bootDiagEnabled
                SqlEolVersion            = $sqlEolVersion
                SqlNoBackup              = $sqlNoBackup
                MmaInstalled             = $mmaInstalled

                # Informational checks (bool)
                NoTags                   = $noTags
                IsSpotInstance           = $isSpot
                EphemeralOsDisk          = $ephemeralOs
                SingleNic                = $singleNic

                # Raw values
                PublicIpAddresses        = ($publicIpList  -join ', ')
                PrivateIpAddresses       = ($privateIpList -join ', ')
                NicCount                 = $nicCount
                InstalledExtensions      = ($extTypesArr -join ', ')
                ExtensionCount           = $extTypesArr.Count
                DataDiskCount            = if ($props.storageProfile.dataDisks) { @($props.storageProfile.dataDisks).Count } else { 0 }
                ManagedIdentityType      = if ($vm.identity) { $identityType } else { 'None' }
                OpenInboundPorts         = if ($hasPublicIp -and $nsgRulesArray.Count -eq 0) { 'unknown (no NSG)' } else { ($openPortsList -join ', ') }

                # SQL VM fields (populated only if IsSqlVm)
                IsSqlVm                  = $isSqlVm
                SqlImageSku              = $sqlImageSku
                SqlLicenseType           = $sqlLicenseType
                SqlConnectivity          = $sqlConnectivity
                SqlManagementMode        = $sqlMgmtMode

                RawFilePath              = $rawFilePath
            }

            $allVms.Add($obj)
        }
    }

    # ── Export CSV report ─────────────────────────────────────────────────────

    if ($OutputPath -and $allVms.Count -gt 0) {
        try {
            $csvFile = Join-Path $OutputPath "AzRA-VirtualMachines_$timestamp.csv"
            $allVms | Select-Object `
                SubscriptionName, SubscriptionId, ResourceGroup, VmName, Location, OsType, VmSize,
                OsImagePublisher, OsImageOffer, OsImageSku, ProvisioningState, PowerState,
                HasPublicIp, RdpExposed, SshExposed, WinRmExposed, SqlPortExposed,
                CustomScriptExtension, RunCommandExtension,
                OsDiskNotEncrypted, DataDiskNotEncrypted,
                EncryptionAtHostDisabled, SecureBootDisabled, VtpmDisabled,
                AadLoginNotConfigured, NoManagedIdentity, BootDiagnosticsEnabled, MmaInstalled,
                IsSqlVm, SqlMixedAuthEnabled, SqlPublicConnectivity, SqlEolVersion, SqlNoBackup,
                NoTags, IsSpotInstance, EphemeralOsDisk, SingleNic,
                PublicIpAddresses, PrivateIpAddresses, InstalledExtensions, OpenInboundPorts,
                ManagedIdentityType, DataDiskCount, NicCount,
                SqlImageSku, SqlLicenseType, SqlConnectivity, SqlManagementMode,
                RawFilePath |
                Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Verbose "Virtual Machines report exported to: $csvFile"
        }
        catch {
            Write-Warning "Could not export Virtual Machines CSV: $_"
        }
    }

    return $allVms.ToArray()
}
