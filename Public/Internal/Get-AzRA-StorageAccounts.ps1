# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-StorageAccounts {
    <#
    .SYNOPSIS
    Enumerates Azure Storage Accounts and audits them for security misconfigurations across all accessible subscriptions.

    .DESCRIPTION
    Iterates across all accessible subscriptions (or a specific one), lists all Storage Accounts,
    and evaluates each against a set of critical, high, and informational security checks:

      Critical:     Public containers (Container/Blob level), no firewall, shared key access enabled
      High:         HTTPS not enforced, weak TLS (1.0/1.1), no key/SAS expiration policy,
                    blob public access allowed at account level
      Informational: Firewall bypass for Azure Services, no customer-managed keys

    For containers with Container-level public access, automatically attempts anonymous blob listing
    to demonstrate real-world impact (no authentication required).

    When -ScanSecrets is specified, retrieves storage account access keys and builds connection
    strings. Keys are exported to a separate secrets CSV.

    Required permissions:
      Microsoft.Storage/storageAccounts/read
      Microsoft.Storage/storageAccounts/blobServices/containers/read
      Microsoft.Storage/storageAccounts/listkeys/action  (only for -ScanSecrets)

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription by ID. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where all output is saved. Raw JSON dumps are saved under:
      <OutputPath>\StorageAccountsRawDump\<SubscriptionName>\<AccountName>\account.json
      <OutputPath>\StorageAccountsRawDump\<SubscriptionName>\<AccountName>\containers.json
    CSV reports are saved as:
      <OutputPath>\AzRA-StorageAccounts_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-StorageAccounts-Secrets_<yyyyMMdd-HHmm>.csv  (only if -ScanSecrets)

    .PARAMETER ScanSecrets
    If specified, calls the listKeys API for each account where shared key access is not
    explicitly disabled. Retrieves key names, values, and constructs full connection strings.
    Exports results to a separate secrets CSV when -OutputPath is also set.

    .PARAMETER MaxRetries
    Maximum retry attempts on throttling (HTTP 429) or transient errors (5xx).
    Must be between 1 and 10. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries (multiplied by attempt number).
    Must be between 1 and 60. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-StorageAccounts -AccessToken $token
    Enumerates all Storage Accounts and returns security metadata to the pipeline.

    .EXAMPLE
    Get-AzRA-StorageAccounts -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Scans a single subscription.

    .EXAMPLE
    Get-AzRA-StorageAccounts -AccessToken $token -OutputPath 'C:\Audit'
    Enumerates all accounts, dumps JSON definitions and exports a metadata CSV.

    .EXAMPLE
    Get-AzRA-StorageAccounts -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets
    Full audit: dumps definitions, metadata CSV, and a secrets CSV with access keys.

    .EXAMPLE
    Get-AzRA-StorageAccounts -AccessToken $token |
        Where-Object { $_.HasPublicContainers } |
        Select-Object StorageAccountName, ResourceGroup, PublicContainerNames, AnonymousBlobs
    Returns only accounts with publicly accessible Container-level blobs.

    .EXAMPLE
    Get-AzRA-StorageAccounts -AccessToken $token |
        Where-Object { $_.NoFirewall -and $_.SharedKeyAccessEnabled } |
        Select-Object StorageAccountName, ResourceGroup
    Returns accounts with no firewall AND shared key access enabled (highest risk).

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Each object contains identity fields, boolean security check results, container summary,
    anonymous blob listing results, and optional key findings.

    .LINK
    https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts
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
        [switch]$ScanSecrets,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySec = 5
    )

    # ── Private helpers ───────────────────────────────────────────────────────

    function Get-RgFromId {
        param([string]$ResourceId)
        if ($ResourceId -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
        return $null
    }

    function Get-StorageApiHeaders {
        return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    }

    # ── Initialization ────────────────────────────────────────────────────────

    $allAccounts = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSecrets  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp   = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot    = $null

    # Prepare output directory (fail fast)
    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
            $dumpRoot = Join-Path $OutputPath 'StorageAccountsRawDump'
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

        # List all storage accounts in subscription
        $accounts = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Storage/storageAccounts?api-version=2024-01-01" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $accounts) {
            Write-Verbose "  No Storage Accounts found in $subName"
            continue
        }

        Write-Verbose "  Storage Accounts found: $($accounts.Count)"

        foreach ($account in $accounts) {
            $accountName = $account.name
            $rgName      = Get-RgFromId -ResourceId $account.id

            if (-not $rgName) {
                Write-Warning "  Could not extract Resource Group for account '$accountName'"
                continue
            }

            Write-Verbose "  Processing: $accountName ($rgName)"

            $props = $account.properties

            # ── Security checks ───────────────────────────────────────────────

            # Critical
            $noFirewall             = ($props.networkAcls.defaultAction -eq 'Allow')
            $sharedKeyAccessEnabled = ($props.allowSharedKeyAccess -ne $false)   # null = enabled

            # High
            $httpsNotEnforced       = ($props.supportsHttpsTrafficOnly -eq $false)
            $weakTls                = ($props.minimumTlsVersion -in @('TLS1_0', 'TLS1_1'))
            $noKeyPolicy            = ($null -eq $props.keyPolicy)
            $noSasPolicy            = ($null -eq $props.sasPolicy)
            $blobPublicAtAccount    = ($props.allowBlobPublicAccess -eq $true)

            # Informational
            $bypassStr              = [string]($props.networkAcls.bypass)
            $firewallBypassAzSvc    = ($bypassStr -match 'AzureServices')
            $noCustomerManagedKeys  = ($props.encryption.keySource -ne 'Microsoft.Keyvault')

            # ── Container enumeration ─────────────────────────────────────────

            $containers = $null
            try {
                $containers = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Storage/storageAccounts/$accountName/blobServices/default/containers?api-version=2024-01-01" `
                    -AccessToken $AccessToken -Method GET -EnablePagination
            }
            catch {
                Write-Warning "  Could not enumerate containers for '$accountName': $_"
            }

            $publicContainerNames     = [System.Collections.Generic.List[string]]::new()
            $blobPublicContainerNames = [System.Collections.Generic.List[string]]::new()
            $anonymousBlobs           = [System.Collections.Generic.List[string]]::new()

            if ($containers) {
                foreach ($container in $containers) {
                    $accessLevel = $container.properties.publicAccess

                    if ($accessLevel -eq 'Container') {
                        $publicContainerNames.Add($container.name)

                        # ── Anonymous blob listing ──────────────────────────
                        $blobListUri = "https://$accountName.blob.core.windows.net/$($container.name)?restype=container&comp=list&maxresults=100"
                        try {
                            $rawXml = Invoke-AzWithRetry `
                                -OperationName "AnonBlobList: $accountName/$($container.name)" `
                                -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec `
                                -ScriptBlock {
                                    # No Authorization header — anonymous call
                                    Invoke-RestMethod -Uri $blobListUri -Method GET -ErrorAction Stop
                                }

                            # Invoke-RestMethod may auto-parse XML into XmlDocument
                            if ($rawXml -is [System.Xml.XmlDocument]) {
                                $blobNodes = $rawXml.EnumerationResults.Blobs.Blob
                            }
                            else {
                                [xml]$parsedXml = [string]$rawXml
                                $blobNodes = $parsedXml.EnumerationResults.Blobs.Blob
                            }

                            foreach ($b in $blobNodes) { $anonymousBlobs.Add($b.Name) }
                            Write-Verbose "    [CRITICAL] $($blobNodes.Count) anonymous blob(s) in $accountName/$($container.name)"
                        }
                        catch {
                            Write-Verbose "    Anonymous listing failed for $accountName/$($container.name): $_"
                        }
                    }
                    elseif ($accessLevel -eq 'Blob') {
                        $blobPublicContainerNames.Add($container.name)
                    }
                }
            }

            # ── Key scanning ──────────────────────────────────────────────────

            $keyFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

            if ($ScanSecrets -and $sharedKeyAccessEnabled) {
                $listKeysUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Storage/storageAccounts/$accountName/listKeys?api-version=2024-01-01"
                try {
                    $keysResponse = Invoke-AzWithRetry `
                        -OperationName "ListKeys: $accountName" `
                        -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec `
                        -ScriptBlock {
                            Invoke-RestMethod -Uri $listKeysUri `
                                -Headers (Get-StorageApiHeaders) `
                                -Method POST -ErrorAction Stop
                        }

                    foreach ($key in $keysResponse.keys) {
                        $connStr = "DefaultEndpointsProtocol=https;AccountName=$accountName;" +
                                   "AccountKey=$($key.value);EndpointSuffix=core.windows.net"

                        $keyFindings.Add([PSCustomObject]@{
                            KeyName          = $key.keyName
                            KeyValue         = $key.value
                            Permissions      = $key.permissions
                            ConnectionString = $connStr
                        })

                        $allSecrets.Add([PSCustomObject]@{
                            SubscriptionName   = $subName
                            SubscriptionId     = $subId
                            ResourceGroup      = $rgName
                            StorageAccountName = $accountName
                            KeyName            = $key.keyName
                            KeyValue           = $key.value
                            Permissions        = $key.permissions
                            ConnectionString   = $connStr
                        })
                    }

                    Write-Verbose "  [SECRET] Keys retrieved for $accountName ($($keyFindings.Count) key(s))"
                }
                catch {
                    Write-Warning "  Could not retrieve keys for '$accountName': $_"
                }
            }

            # ── Raw dump ──────────────────────────────────────────────────────

            $rawFilePath = $null
            if ($dumpRoot) {
                $safeSubName     = $subName     -replace '[^a-zA-Z0-9_\-]', '_'
                $safeAccountName = $accountName -replace '[^a-zA-Z0-9_\-]', '_'
                $accountDumpDir  = Join-Path (Join-Path $dumpRoot $safeSubName) $safeAccountName

                if (-not (Test-Path $accountDumpDir)) {
                    try {
                        New-Item -ItemType Directory -Force -Path $accountDumpDir -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Warning "  Could not create dump directory '$accountDumpDir': $_"
                    }
                }

                if (Test-Path $accountDumpDir) {
                    # account.json
                    try {
                        $account | ConvertTo-Json -Depth 20 |
                            Set-Content -Path (Join-Path $accountDumpDir 'account.json') -Encoding UTF8 -ErrorAction Stop
                    }
                    catch { Write-Warning "  Could not write account.json for '$accountName': $_" }

                    # containers.json
                    if ($containers) {
                        try {
                            $containers | ConvertTo-Json -Depth 10 |
                                Set-Content -Path (Join-Path $accountDumpDir 'containers.json') -Encoding UTF8 -ErrorAction Stop
                        }
                        catch { Write-Warning "  Could not write containers.json for '$accountName': $_" }
                    }

                    $rawFilePath = $accountDumpDir
                    Write-Verbose "  Dumped: $accountDumpDir"
                }
            }

            # ── Build pipeline object ─────────────────────────────────────────

            $obj = [PSCustomObject]@{
                # Identity
                SubscriptionId                   = $subId
                SubscriptionName                 = $subName
                ResourceGroup                    = $rgName
                StorageAccountName               = $accountName
                Location                         = $account.location
                Kind                             = $account.kind
                Sku                              = $account.sku.name
                CreationTime                     = $props.creationTime
                PrimaryLocation                  = $props.primaryLocation

                # Critical findings (bool)
                HasPublicContainers              = ($publicContainerNames.Count -gt 0)
                HasBlobPublicContainers          = ($blobPublicContainerNames.Count -gt 0)
                NoFirewall                       = $noFirewall
                SharedKeyAccessEnabled           = $sharedKeyAccessEnabled

                # High findings (bool)
                HttpsNotEnforced                 = $httpsNotEnforced
                WeakTlsVersion                   = $weakTls
                NoKeyExpirationPolicy            = $noKeyPolicy
                NoSasExpirationPolicy            = $noSasPolicy
                BlobPublicAccessAllowedAtAccount = $blobPublicAtAccount

                # Informational findings (bool)
                FirewallBypassAzureServices      = $firewallBypassAzSvc
                NoCustomerManagedKeys            = $noCustomerManagedKeys

                # Raw config values (direct mirror of Azure API properties)
                HttpsTrafficOnlyEnabled          = $props.supportsHttpsTrafficOnly
                MinimumTlsVersion                = $props.minimumTlsVersion
                NetworkDefaultAction             = $props.networkAcls.defaultAction
                NetworkBypass                    = $bypassStr
                EncryptionKeySource              = $props.encryption.keySource

                # Container summary
                ContainerCount                   = if ($containers) { @($containers).Count } else { 0 }
                PublicContainerCount             = $publicContainerNames.Count
                BlobPublicContainerCount         = $blobPublicContainerNames.Count
                PublicContainerNames             = ($publicContainerNames -join ', ')

                # Anonymous blob listing
                AnonymousBlobCount               = $anonymousBlobs.Count
                AnonymousBlobs                   = ($anonymousBlobs -join ', ')

                # Key findings (populated by -ScanSecrets)
                KeyFindings                      = $keyFindings.ToArray()
                HasKeyFindings                   = ($keyFindings.Count -gt 0)

                RawFilePath                      = $rawFilePath
            }

            $allAccounts.Add($obj)
        }
    }

    # ── Export CSV reports ────────────────────────────────────────────────────

    if ($OutputPath -and $allAccounts.Count -gt 0) {
        try {
            $csvFile = Join-Path $OutputPath "AzRA-StorageAccounts_$timestamp.csv"
            $allAccounts | Select-Object `
                SubscriptionName, SubscriptionId, ResourceGroup, StorageAccountName,
                Location, Kind, Sku, CreationTime, PrimaryLocation,
                HasPublicContainers, HasBlobPublicContainers, NoFirewall, SharedKeyAccessEnabled,
                HttpsNotEnforced, WeakTlsVersion, NoKeyExpirationPolicy, NoSasExpirationPolicy,
                BlobPublicAccessAllowedAtAccount,
                FirewallBypassAzureServices, NoCustomerManagedKeys,
                HttpsTrafficOnlyEnabled, MinimumTlsVersion, NetworkDefaultAction, NetworkBypass, EncryptionKeySource,
                ContainerCount, PublicContainerCount, BlobPublicContainerCount, PublicContainerNames,
                AnonymousBlobCount, AnonymousBlobs,
                HasKeyFindings, RawFilePath |
                Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Verbose "Storage Accounts report exported to: $csvFile"
        }
        catch {
            Write-Warning "Could not export Storage Accounts CSV: $_"
        }
    }

    if ($OutputPath -and $ScanSecrets -and $allSecrets.Count -gt 0) {
        try {
            $secretsCsv = Join-Path $OutputPath "AzRA-StorageAccounts-Secrets_$timestamp.csv"
            $allSecrets | Export-Csv -Path $secretsCsv -NoTypeInformation -Encoding UTF8
            Write-Verbose "Secrets report exported to: $secretsCsv"
        }
        catch {
            Write-Warning "Could not export secrets CSV: $_"
        }
    }

    return $allAccounts.ToArray()
}
