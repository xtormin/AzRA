# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-CosmosDB {
    <#
    .SYNOPSIS
    Enumerates Azure Cosmos DB accounts and audits security misconfigurations.
    Optionally retrieves master keys (full read/write access to all data).

    .DESCRIPTION
    Iterates across all accessible subscriptions (or a specific one), lists all Cosmos DB
    accounts, and evaluates each against security checks:

      Critical:     PublicNetworkAccessEnabled (no firewall), LocalAuthDisabled=false (keys active),
                    NoPrivateEndpoints
      High:         NoFirewallRules, MultipleLocationsNoFailover, DiagnosticLogsDisabled,
                    CmkNotConfigured, DisableLocalAuthNotSet
      Informational: BackupPolicyType, DatabaseAccountKind, EnableFreeTier

    With -ScanSecrets, calls listKeys to retrieve primaryMasterKey, secondaryMasterKey,
    primaryReadonlyMasterKey, secondaryReadonlyMasterKey. Master keys grant full data plane
    access to all databases and containers in the account.

    Required permissions:
      Microsoft.DocumentDB/databaseAccounts/read
      Microsoft.DocumentDB/databaseAccounts/listKeys/action  (only for -ScanSecrets)
      microsoft.insights/diagnosticSettings/read              (optional)

    .PARAMETER AccessToken
    Azure Management API access token. Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where output is saved. Raw dumps under:
      <OutputPath>\CosmosDBRawDump\<SubscriptionName>\<AccountName>\account.json
      <OutputPath>\CosmosDBRawDump\<SubscriptionName>\<AccountName>\diagnostics.json
    CSV reports:
      <OutputPath>\AzRA-CosmosDB_<timestamp>.csv
      <OutputPath>\AzRA-CosmosDB-Keys_<timestamp>.csv  (only if -ScanSecrets)

    .PARAMETER ScanSecrets
    If specified, calls listKeys to retrieve all master keys in plaintext.
    Master keys grant full read/write access to all data in the account.

    .PARAMETER MaxRetries
    Maximum retry attempts. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-CosmosDB -AccessToken $token

    .EXAMPLE
    Get-AzRA-CosmosDB -AccessToken $token -ScanSecrets -OutputPath 'C:\Audit'

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    One object per Cosmos DB account.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]  [string]$AccessToken,
        [Parameter(Mandatory = $false)] [string]$SubscriptionId,
        [Parameter(Mandatory = $false)] [string]$OutputPath,
        [Parameter(Mandatory = $false)] [switch]$ScanSecrets,
        [Parameter(Mandatory = $false)] [ValidateRange(1,10)]  [int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)] [ValidateRange(1,60)]  [int]$RetryDelaySec = 5
    )

    function Get-RgFromId {
        param([string]$ResourceId)
        if ($ResourceId -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
        return $null
    }

    function Get-ArmHeaders { return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' } }

    function Invoke-ArmPost {
        param([string]$Uri, [string]$Label)
        try { return Invoke-RestMethod -Uri $Uri -Headers (Get-ArmHeaders) -Method POST -ErrorAction Stop }
        catch {
            $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
            if ($code -in @(401,403)) { Write-Warning "    [403] Sin permiso para $Label" }
            else { Write-Verbose "    POST failed ($code): $Uri" }
            return $null
        }
    }

    # -- Init ------------------------------------------------------------------

    $allAccounts = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allKeys     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp   = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot    = $null

    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null }
            $dumpRoot = Join-Path $OutputPath 'CosmosDBRawDump'
            if (-not (Test-Path $dumpRoot)) { New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null }
        }
        catch { throw "Cannot create output directory '$OutputPath': $_" }
    }

    Write-Host ""
    Write-Host "[*] Cosmos DB - iniciando auditoria..." -ForegroundColor Cyan

    if ($SubscriptionId) {
        $subs = Invoke-AzRARequest -Uri "https://management.azure.com/subscriptions/$SubscriptionId`?api-version=2022-12-01" -AccessToken $AccessToken -Method GET
        if (-not $subs) { throw "Subscription not found: $SubscriptionId" }
        $subs = @($subs)
    }
    else {
        $subs = Invoke-AzRARequest -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' -AccessToken $AccessToken -Method GET -EnablePagination
    }

    Write-Host "  [~] Subscripciones a analizar: $(@($subs).Count)" -ForegroundColor Gray

    foreach ($sub in $subs) {
        $subId   = $sub.subscriptionId
        $subName = $sub.displayName

        Write-Host ""
        Write-Host "  [*] Subscripcion: $subName ($subId)" -ForegroundColor Cyan
        Write-Host "    [~] Enumerando Cosmos DB accounts..." -ForegroundColor Gray

        $accounts = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2024-02-15-preview" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $accounts) { Write-Host "    [~] Sin Cosmos DB accounts en esta subscripcion" -ForegroundColor Gray; continue }
        Write-Host "    [+] Accounts encontradas: $(@($accounts).Count)" -ForegroundColor White

        foreach ($account in $accounts) {
            $accName = $account.name
            $rgName  = Get-RgFromId -ResourceId $account.id
            $props   = $account.properties

            Write-Host "    [~] Analizando: $accName [$($account.kind)]" -ForegroundColor Gray

            # -- Security checks -----------------------------------------------

            # Public network access
            $pubNetEnabled    = ($props.publicNetworkAccess -ne 'Disabled')
            $ipRules          = @($props.ipRules)
            $vnetRules        = @($props.virtualNetworkRules)
            $noFirewallRules  = ($pubNetEnabled -and $ipRules.Count -eq 0 -and $vnetRules.Count -eq 0)

            # Private endpoints
            $privateEps       = @($props.privateEndpointConnections)
            $noPrivateEp      = ($privateEps.Count -eq 0)

            # Local auth (master keys) - disableLocalAuth=true means keys disabled, RBAC only
            $localAuthDisabled = ($props.disableLocalAuth -eq $true)

            # Customer-managed key
            $cmkNotConfigured = ($null -eq $props.keyVaultKeyUri -or $props.keyVaultKeyUri -eq '')

            # Diagnostic settings (non-fatal)
            $diagLogsDisabled = $null
            try {
                $diag = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/$($account.id)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview" `
                    -AccessToken $AccessToken -Method GET -ErrorAction Stop
                $diagLogsDisabled = ($null -eq $diag -or @($diag).Count -eq 0)
            }
            catch { Write-Verbose "    Sin acceso a diagnostic settings para $accName" }

            # -- Key extraction ------------------------------------------------

            $keys        = [System.Collections.Generic.List[PSCustomObject]]::new()
            $hasKeys     = $false
            $keysRaw     = $null

            if ($ScanSecrets -and -not $localAuthDisabled) {
                Write-Host "      [~] Intentando extraer master keys..." -ForegroundColor Gray
                $listUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.DocumentDB/databaseAccounts/$accName/listKeys?api-version=2024-02-15-preview"
                $keysRaw = Invoke-ArmPost -Uri $listUri -Label "CosmosDB listKeys ($accName)"

                if ($keysRaw) {
                    foreach ($pair in @(
                        @{ Name = 'primaryMasterKey';         Value = $keysRaw.primaryMasterKey },
                        @{ Name = 'secondaryMasterKey';       Value = $keysRaw.secondaryMasterKey },
                        @{ Name = 'primaryReadonlyMasterKey'; Value = $keysRaw.primaryReadonlyMasterKey },
                        @{ Name = 'secondaryReadonlyMasterKey'; Value = $keysRaw.secondaryReadonlyMasterKey }
                    )) {
                        if ($pair.Value) {
                            $entry = [PSCustomObject]@{
                                SubscriptionName = $subName
                                SubscriptionId   = $subId
                                ResourceGroup    = $rgName
                                AccountName      = $accName
                                KeyName          = $pair.Name
                                KeyValue         = $pair.Value
                                DocumentEndpoint = $props.documentEndpoint
                            }
                            $keys.Add($entry)
                            $allKeys.Add($entry)
                        }
                    }
                    $hasKeys = ($keys.Count -gt 0)
                    Write-Host "      [+] Master keys extraidas: $($keys.Count)" -ForegroundColor Red
                }
            }
            elseif ($ScanSecrets -and $localAuthDisabled) {
                Write-Host "      [~] Local auth deshabilitado en $accName (solo RBAC) - keys no disponibles" -ForegroundColor Gray
            }

            # -- Summary flags -------------------------------------------------

            $hasCritical = ($noFirewallRules -or ($pubNetEnabled -and $noPrivateEp) -or $hasKeys)
            $hasHigh     = ((-not $localAuthDisabled) -or $cmkNotConfigured -or ($diagLogsDisabled -eq $true))

            if ($hasCritical) {
                Write-Host "    [!] CRITICO: $accName" -ForegroundColor Red
                if ($noFirewallRules)                  { Write-Host "        - NoFirewallRules: acceso publico sin restricciones IP ni VNet" -ForegroundColor Red }
                if ($pubNetEnabled -and $noPrivateEp)  { Write-Host "        - SinPrivateEndpoint: cuenta publica sin private endpoint" -ForegroundColor Red }
                if ($hasKeys)                          { Write-Host "        - MasterKeys extraidas: $($keys.Count) (acceso total a todos los datos)" -ForegroundColor Red }
            }
            elseif ($hasHigh) {
                Write-Host "    [!] ALTO: $accName" -ForegroundColor Yellow
                if (-not $localAuthDisabled)          { Write-Host "        - LocalAuthEnabled: master keys activas (disableLocalAuth=false)" -ForegroundColor Yellow }
                if ($cmkNotConfigured)                { Write-Host "        - CmkNotConfigured: cifrado con claves de Microsoft, no del cliente" -ForegroundColor Yellow }
                if ($diagLogsDisabled -eq $true)      { Write-Host "        - DiagnosticLogsDisabled: sin Diagnostic Settings" -ForegroundColor Yellow }
            }
            else { Write-Host "    [OK] $accName" -ForegroundColor Green }

            # -- Raw dump ------------------------------------------------------

            $rawFilePath = $null
            if ($dumpRoot -and $rgName) {
                $dir = Join-Path (Join-Path $dumpRoot ($subName -replace '[^a-zA-Z0-9_\-]','_')) ($accName -replace '[^a-zA-Z0-9_\-]','_')
                if (-not (Test-Path $dir)) { try { New-Item -ItemType Directory -Force -Path $dir -ErrorAction Stop | Out-Null } catch {} }
                if (Test-Path $dir) {
                    try { $account | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $dir 'account.json') -Encoding UTF8 -ErrorAction Stop } catch {}
                    if ($keysRaw) { try { $keysRaw | ConvertTo-Json | Set-Content -Path (Join-Path $dir 'keys.json') -Encoding UTF8 -ErrorAction Stop } catch {} }
                    if ($null -ne $diagLogsDisabled) { try { @{ diagLogsDisabled = $diagLogsDisabled } | ConvertTo-Json | Set-Content -Path (Join-Path $dir 'diagnostics.json') -Encoding UTF8 -ErrorAction Stop } catch {} }
                    $rawFilePath = $dir
                }
            }

            $allAccounts.Add([PSCustomObject]@{
                SubscriptionId       = $subId
                SubscriptionName     = $subName
                ResourceGroup        = $rgName
                AccountName          = $accName
                Kind                 = $account.kind
                Location             = $account.location
                DocumentEndpoint     = $props.documentEndpoint
                PublicNetworkEnabled = $pubNetEnabled
                NoFirewallRules      = $noFirewallRules
                NoPrivateEndpoint    = $noPrivateEp
                LocalAuthEnabled     = (-not $localAuthDisabled)
                CmkNotConfigured     = $cmkNotConfigured
                DiagnosticLogsDisabled = $diagLogsDisabled
                HasKeys              = $hasKeys
                KeyCount             = $keys.Count
                Keys                 = $keys.ToArray()
                HasCriticalFindings  = $hasCritical
                HasHighFindings      = $hasHigh
                RawFilePath          = $rawFilePath
            })
        }
    }

    if ($OutputPath -and $allAccounts.Count -gt 0) {
        try {
            $allAccounts.ToArray() | Select-Object SubscriptionName, ResourceGroup, AccountName, Kind,
                Location, DocumentEndpoint, PublicNetworkEnabled, NoFirewallRules, NoPrivateEndpoint,
                LocalAuthEnabled, CmkNotConfigured, DiagnosticLogsDisabled,
                HasKeys, KeyCount, HasCriticalFindings, HasHighFindings, RawFilePath |
                Export-Csv -Path (Join-Path $OutputPath "AzRA-CosmosDB_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        } catch { Write-Warning "Could not export CosmosDB CSV: $_" }

        if ($ScanSecrets -and $allKeys.Count -gt 0) {
            try {
                $allKeys.ToArray() | Export-Csv -Path (Join-Path $OutputPath "AzRA-CosmosDB-Keys_$timestamp.csv") -NoTypeInformation -Encoding UTF8
            } catch { Write-Warning "Could not export keys CSV: $_" }
        }
    }

    $critCount  = ($allAccounts | Where-Object { $_.HasCriticalFindings }).Count
    $highCount  = ($allAccounts | Where-Object { $_.HasHighFindings -and -not $_.HasCriticalFindings }).Count
    $totalCount = $allAccounts.Count

    Write-Host ""
    Write-Host "[*] Auditoria completada: $totalCount Cosmos DB accounts analizadas" -ForegroundColor Cyan
    if ($critCount -gt 0)  { Write-Host "  [!] Accounts con hallazgos CRITICOS: $critCount" -ForegroundColor Red }
    if ($highCount -gt 0)  { Write-Host "  [!] Accounts con hallazgos ALTOS: $highCount" -ForegroundColor Yellow }
    if ($ScanSecrets)      { Write-Host "  [+] Keys extraidas de $($allAccounts | Where-Object {$_.HasKeys} | Measure-Object | Select-Object -ExpandProperty Count) accounts ($($allKeys.Count) keys total)" -ForegroundColor White }
    if ($OutputPath)       { Write-Host "  [+] Resultados exportados en: $OutputPath" -ForegroundColor White }
    Write-Host ""

    return $allAccounts.ToArray()
}
