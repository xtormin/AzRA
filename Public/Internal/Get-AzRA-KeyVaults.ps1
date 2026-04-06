# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-KeyVaults {
    <#
    .SYNOPSIS
    Enumerates Azure Key Vaults and audits them for security misconfigurations across all accessible subscriptions.

    .DESCRIPTION
    Iterates across all accessible subscriptions (or a specific one), lists all Key Vaults,
    and evaluates each against a set of critical, high, and informational security checks:

      Critical:     Soft delete disabled, purge protection disabled, public network access with no
                    firewall, legacy access policies (vault-based) instead of RBAC
      High:         Overly permissive access policies, vault enabled for VM deployment / disk
                    encryption / ARM template deployment, weak soft-delete retention (< 30 days),
                    no firewall configured, no diagnostic settings (audit logging)
      Informational: Azure Services firewall bypass, no private endpoint, Standard SKU (no HSM)

    When -ScanSecrets is specified together with -VaultToken (a token scoped to
    https://vault.azure.net/), the function also queries the Key Vault Data Plane to list
    secret, key, and certificate metadata (names and expiry — NOT actual secret values).

    Required ARM permissions:
      Microsoft.KeyVault/vaults/read
      Microsoft.Insights/diagnosticSettings/read  (optional — non-fatal if missing)

    Required Data Plane permissions (only with -ScanSecrets + -VaultToken):
      Secret List, Key List, Certificate List on the target vault

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription by ID. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where all output is saved. Raw JSON dumps are saved under:
      <OutputPath>\KeyVaultsRawDump\<SubscriptionName>\<VaultName>\vault.json
      <OutputPath>\KeyVaultsRawDump\<SubscriptionName>\<VaultName>\diagnostics.json
    CSV reports are saved as:
      <OutputPath>\AzRA-KeyVaults_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-KeyVaults-Secrets_<yyyyMMdd-HHmm>.csv  (only if -ScanSecrets and -VaultToken)

    .PARAMETER VaultToken
    Azure Key Vault Data Plane access token (JWT), scoped to https://vault.azure.net/.
    Required when using -ScanSecrets to query the data plane. Obtain with:
      (az account get-access-token --resource https://vault.azure.net/ | ConvertFrom-Json).accessToken

    .PARAMETER ScanSecrets
    If specified (together with -VaultToken), queries each vault's data plane to list
    secret, key, and certificate metadata (names, enabled state, expiry dates).
    Actual secret values are NOT retrieved — only the item list and metadata.
    Exports results to a separate CSV when -OutputPath is also set.

    .PARAMETER MaxRetries
    Maximum retry attempts on throttling (HTTP 429) or transient errors (5xx).
    Must be between 1 and 10. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries (multiplied by attempt number).
    Must be between 1 and 60. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-KeyVaults -AccessToken $token
    Enumerates all Key Vaults and returns security metadata to the pipeline.

    .EXAMPLE
    Get-AzRA-KeyVaults -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Scans a single subscription.

    .EXAMPLE
    Get-AzRA-KeyVaults -AccessToken $token -OutputPath 'C:\Audit'
    Enumerates all vaults, dumps JSON definitions and exports a metadata CSV.

    .EXAMPLE
    $token      = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    $vaultToken = (az account get-access-token --resource https://vault.azure.net/ | ConvertFrom-Json).accessToken
    Get-AzRA-KeyVaults -AccessToken $token -VaultToken $vaultToken -ScanSecrets -OutputPath 'C:\Audit'
    Full audit: dumps definitions, metadata CSV, and a secrets CSV with data plane item listing.

    .EXAMPLE
    Get-AzRA-KeyVaults -AccessToken $token |
        Where-Object { $_.NotRecoverable -or $_.PublicNetworkAccess -or $_.LegacyAccessPolicies }
    Returns only vaults with critical misconfigurations.

    .EXAMPLE
    Get-AzRA-KeyVaults -AccessToken $token |
        Where-Object { $_.OverlyPermissiveAccessPolicies } |
        Select-Object VaultName, ResourceGroup, AccessPolicyCount
    Returns vaults with access policies granting excessive permissions.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Each object contains identity fields, boolean security check results, raw config values,
    and optional data plane item metadata.

    .LINK
    https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults
    https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secrets/get-secrets
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
        [string]$VaultToken,

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

    function Get-ArmHeaders {
        return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    }

    function Get-VaultHeaders {
        return @{ 'Authorization' = "Bearer $VaultToken"; 'Content-Type' = 'application/json' }
    }

    # Retrieves all pages from a data-plane list endpoint (vault.azure.net nextLink)
    function Get-VaultDataPlaneList {
        param([string]$Uri, [string]$ItemType)
        $results = [System.Collections.Generic.List[object]]::new()
        $currentUri = $Uri
        do {
            try {
                $response = Invoke-AzWithRetry `
                    -OperationName "DataPlane $ItemType list" `
                    -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec `
                    -ScriptBlock {
                        Invoke-RestMethod -Uri $currentUri -Headers (Get-VaultHeaders) -Method GET -ErrorAction Stop
                    }
                if ($response.value) { foreach ($item in $response.value) { $results.Add($item) } }
                $currentUri = $response.nextLink
            }
            catch {
                Write-Warning "    Data plane list failed ($ItemType): $_"
                $currentUri = $null
            }
        } while ($currentUri)
        return $results
    }

    # ── Initialization ────────────────────────────────────────────────────────

    $allVaults      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSecretItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp      = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot       = $null

    # Validate parameter combinations
    if ($ScanSecrets -and -not $VaultToken) {
        Write-Warning "-ScanSecrets requires -VaultToken (scope: https://vault.azure.net/). Data plane will be skipped."
    }
    if ($VaultToken -and -not $ScanSecrets) {
        Write-Warning "-VaultToken was provided but -ScanSecrets was not specified. Vault token will be ignored."
    }

    $doDataPlane = ($ScanSecrets -and $VaultToken)

    # Prepare output directory (fail fast)
    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
            $dumpRoot = Join-Path $OutputPath 'KeyVaultsRawDump'
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

        # List vaults — note: response includes id/name/location/tags but NOT full properties
        $vaults = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.KeyVault/vaults?api-version=2024-11-01" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $vaults) {
            Write-Verbose "  No Key Vaults found in $subName"
            continue
        }

        Write-Verbose "  Key Vaults found: $($vaults.Count)"

        foreach ($vault in $vaults) {
            $vaultName = $vault.name
            $rgName    = Get-RgFromId -ResourceId $vault.id

            if (-not $rgName) {
                Write-Warning "  Could not extract Resource Group for vault '$vaultName'"
                continue
            }

            Write-Verbose "  Processing: $vaultName ($rgName)"

            # ── GET full vault properties ─────────────────────────────────────
            # The list endpoint omits accessPolicies, networkAcls, etc.

            $vaultFull = $null
            try {
                $vaultFull = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.KeyVault/vaults/$vaultName`?api-version=2024-11-01" `
                    -AccessToken $AccessToken -Method GET
            }
            catch {
                Write-Warning "  Could not retrieve full properties for vault '$vaultName': $_"
            }

            $props = if ($vaultFull) { $vaultFull.properties } else { $null }

            # ── Security checks ───────────────────────────────────────────────

            # --- Critical ---
            # null → treat as disabled (conservative posture for pre-2020 vaults)
            $softDeleteDisabled      = ($props.enableSoftDelete -ne $true)
            $purgeProtDisabled       = ($props.enablePurgeProtection -ne $true)
            $notRecoverable          = ($softDeleteDisabled -or $purgeProtDisabled)

            # Public network access: property may be absent on older vaults (assume enabled)
            $pubNetAccess            = $props.publicNetworkAccess
            $netDefaultAction        = $props.networkAcls.defaultAction
            $publicNetworkAccess     = ($pubNetAccess -ne 'Disabled') -and ($netDefaultAction -eq 'Allow')

            # RBAC vs Access Policies
            $rbacEnabled             = ($props.enableRbacAuthorization -eq $true)
            $legacyAccessPolicies    = (-not $rbacEnabled)

            # --- High ---
            # Overly permissive: any policy grants 'all' or >= 8 permissions in any category
            $overlyPermissive = $false
            if ($props.accessPolicies) {
                foreach ($policy in $props.accessPolicies) {
                    $permSets = @(
                        $policy.permissions.secrets,
                        $policy.permissions.keys,
                        $policy.permissions.certificates
                    )
                    foreach ($permSet in $permSets) {
                        if ($permSet) {
                            $permArray = @($permSet)
                            if ($permArray -contains 'all' -or $permArray.Count -ge 8) {
                                $overlyPermissive = $true
                                break
                            }
                        }
                    }
                    if ($overlyPermissive) { break }
                }
            }

            $enabledForDeployment         = ($props.enabledForDeployment -eq $true)
            $enabledForDiskEncryption     = ($props.enabledForDiskEncryption -eq $true)
            $enabledForTemplateDeployment = ($props.enabledForTemplateDeployment -eq $true)

            $retentionDays           = $props.softDeleteRetentionInDays
            $weakSoftDeleteRetention = ($retentionDays -ne $null -and [int]$retentionDays -lt 30)

            $noFirewall              = ($netDefaultAction -eq 'Allow')

            # --- Informational ---
            $bypassStr               = [string]($props.networkAcls.bypass)
            $firewallBypassAzSvc     = ($bypassStr -match 'AzureServices')

            $privateEndpoints        = $props.privateEndpointConnections
            $noPrivateEndpoint       = (-not $privateEndpoints -or @($privateEndpoints).Count -eq 0)

            $standardSku             = ($props.sku.name -eq 'standard')

            $accessPolicyCount       = if ($props.accessPolicies) { @($props.accessPolicies).Count } else { 0 }

            # ── Diagnostic settings ───────────────────────────────────────────

            $noDiagnostics  = $null   # $null = unknown (e.g. 403); $true = confirmed absent
            $diagnosticsObj = $null

            try {
                $diagResponse = Invoke-AzRARequest `
                    -Uri "https://management.azure.com$($vault.id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview" `
                    -AccessToken $AccessToken -Method GET
                # $diagResponse is the array of diagnostic setting objects (or empty)
                $noDiagnostics  = (-not $diagResponse -or @($diagResponse).Count -eq 0)
                $diagnosticsObj = $diagResponse
                if ($noDiagnostics) {
                    Write-Verbose "  [HIGH] No diagnostic settings on $vaultName"
                }
            }
            catch {
                Write-Warning "  Could not retrieve diagnostic settings for '$vaultName' (may lack Microsoft.Insights/read): $_"
                $noDiagnostics = $null
            }

            # ── Data plane — secrets / keys / certificates ────────────────────

            $secretItems = [System.Collections.Generic.List[PSCustomObject]]::new()

            if ($doDataPlane) {
                $vaultUri = $props.vaultUri
                if (-not $vaultUri) { $vaultUri = "https://$vaultName.vault.azure.net" }

                foreach ($itemType in @('secrets', 'keys', 'certificates')) {
                    $items = Get-VaultDataPlaneList -Uri "$vaultUri/$itemType`?api-version=7.4" -ItemType $itemType

                    foreach ($item in $items) {
                        # item.id is like https://vault.azure.net/secrets/mySecret/...
                        # Extract name from the id path segment
                        $itemName = if ($item.id -match "/$itemType/([^/]+)") { $Matches[1] } else { $item.id }

                        $expiry  = $null
                        if ($item.attributes.exp) {
                            try { $expiry = [System.DateTimeOffset]::FromUnixTimeSeconds($item.attributes.exp).UtcDateTime } catch {}
                        }

                        $itemObj = [PSCustomObject]@{
                            ItemType    = $itemType.TrimEnd('s')   # secret / key / certificate
                            ItemName    = $itemName
                            ItemId      = $item.id
                            Enabled     = $item.attributes.enabled
                            Expires     = $expiry
                            ContentType = $item.contentType
                        }
                        $secretItems.Add($itemObj)

                        $allSecretItems.Add([PSCustomObject]@{
                            SubscriptionName = $subName
                            SubscriptionId   = $subId
                            ResourceGroup    = $rgName
                            VaultName        = $vaultName
                            ItemType         = $itemObj.ItemType
                            ItemName         = $itemName
                            ItemId           = $item.id
                            Enabled          = $item.attributes.enabled
                            Expires          = $expiry
                            ContentType      = $item.contentType
                        })
                    }
                }

                Write-Verbose "  Data plane: $($secretItems.Count) item(s) found in $vaultName"
            }

            $hasExpiredSecrets = $false
            $now = Get-Date
            foreach ($si in $secretItems) {
                if ($si.Expires -and $si.Expires -lt $now) { $hasExpiredSecrets = $true; break }
            }

            # ── Raw dump ──────────────────────────────────────────────────────

            $vaultJsonPath = $null
            if ($dumpRoot) {
                $safeSubName   = $subName   -replace '[^a-zA-Z0-9_\-]', '_'
                $safeVaultName = $vaultName -replace '[^a-zA-Z0-9_\-]', '_'
                $vaultDumpDir  = Join-Path (Join-Path $dumpRoot $safeSubName) $safeVaultName

                if (-not (Test-Path $vaultDumpDir)) {
                    try {
                        New-Item -ItemType Directory -Force -Path $vaultDumpDir -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Warning "  Could not create dump directory '$vaultDumpDir': $_"
                    }
                }

                if (Test-Path $vaultDumpDir) {
                    # vault.json — full ARM object
                    $vaultToSave = if ($vaultFull) { $vaultFull } else { $vault }
                    try {
                        $vaultToSave | ConvertTo-Json -Depth 20 |
                            Set-Content -Path (Join-Path $vaultDumpDir 'vault.json') -Encoding UTF8 -ErrorAction Stop
                    }
                    catch { Write-Warning "  Could not write vault.json for '$vaultName': $_" }

                    # diagnostics.json — if retrieved
                    if ($diagnosticsObj) {
                        try {
                            $diagnosticsObj | ConvertTo-Json -Depth 10 |
                                Set-Content -Path (Join-Path $vaultDumpDir 'diagnostics.json') -Encoding UTF8 -ErrorAction Stop
                        }
                        catch { Write-Warning "  Could not write diagnostics.json for '$vaultName': $_" }
                    }

                    $vaultJsonPath = $vaultDumpDir
                    Write-Verbose "  Dumped: $vaultDumpDir"
                }
            }

            # ── Build pipeline object ─────────────────────────────────────────

            $obj = [PSCustomObject]@{
                # Identity
                SubscriptionId                   = $subId
                SubscriptionName                 = $subName
                ResourceGroup                    = $rgName
                VaultName                        = $vaultName
                Location                         = $vault.location
                Sku                              = $props.sku.name
                VaultUri                         = $props.vaultUri
                TenantId                         = $props.tenantId
                Tags                             = if ($vault.tags) { $vault.tags | ConvertTo-Json -Compress -Depth 3 } else { '' }

                # Critical checks (bool)
                NotRecoverable                   = $notRecoverable
                SoftDeleteDisabled               = $softDeleteDisabled
                PurgeProtectionDisabled          = $purgeProtDisabled
                PublicNetworkAccess              = $publicNetworkAccess
                LegacyAccessPolicies             = $legacyAccessPolicies

                # High checks (bool)
                OverlyPermissiveAccessPolicies   = $overlyPermissive
                EnabledForDeployment             = $enabledForDeployment
                EnabledForDiskEncryption         = $enabledForDiskEncryption
                EnabledForTemplateDeployment     = $enabledForTemplateDeployment
                WeakSoftDeleteRetention          = $weakSoftDeleteRetention
                NoFirewall                       = $noFirewall
                NoDiagnosticSettings             = $noDiagnostics

                # Informational checks (bool)
                FirewallBypassAzureServices      = $firewallBypassAzSvc
                NoPrivateEndpoint                = $noPrivateEndpoint
                StandardSku                      = $standardSku

                # Raw config values
                SoftDeleteRetentionDays          = $retentionDays
                NetworkDefaultAction             = $netDefaultAction
                NetworkBypass                    = $bypassStr
                AccessPolicyCount                = $accessPolicyCount
                PublicNetworkAccessRaw           = $pubNetAccess
                RbacEnabled                      = $rbacEnabled

                # Data plane (populated only when -ScanSecrets + -VaultToken)
                SecretCount                      = $secretItems.Count
                SecretItems                      = $secretItems.ToArray()
                HasExpiredSecrets                = $hasExpiredSecrets

                RawFilePath                      = $vaultJsonPath
            }

            $allVaults.Add($obj)
        }
    }

    # ── Export CSV reports ────────────────────────────────────────────────────

    if ($OutputPath -and $allVaults.Count -gt 0) {
        try {
            $csvFile = Join-Path $OutputPath "AzRA-KeyVaults_$timestamp.csv"
            $allVaults | Select-Object `
                SubscriptionName, SubscriptionId, ResourceGroup, VaultName, Location, Sku,
                NotRecoverable, SoftDeleteDisabled, PurgeProtectionDisabled,
                PublicNetworkAccess, LegacyAccessPolicies,
                OverlyPermissiveAccessPolicies, EnabledForDeployment, EnabledForDiskEncryption,
                EnabledForTemplateDeployment, WeakSoftDeleteRetention, NoFirewall, NoDiagnosticSettings,
                FirewallBypassAzureServices, NoPrivateEndpoint, StandardSku,
                SoftDeleteRetentionDays, NetworkDefaultAction, NetworkBypass,
                AccessPolicyCount, PublicNetworkAccessRaw, RbacEnabled,
                SecretCount, HasExpiredSecrets, RawFilePath |
                Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Verbose "Key Vaults report exported to: $csvFile"
        }
        catch {
            Write-Warning "Could not export Key Vaults CSV: $_"
        }
    }

    if ($OutputPath -and $doDataPlane -and $allSecretItems.Count -gt 0) {
        try {
            $secretsCsv = Join-Path $OutputPath "AzRA-KeyVaults-Secrets_$timestamp.csv"
            $allSecretItems | Export-Csv -Path $secretsCsv -NoTypeInformation -Encoding UTF8
            Write-Verbose "Secrets (data plane) report exported to: $secretsCsv"
        }
        catch {
            Write-Warning "Could not export Key Vaults secrets CSV: $_"
        }
    }

    return $allVaults.ToArray()
}
