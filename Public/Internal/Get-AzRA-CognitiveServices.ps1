# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-CognitiveServices {
    <#
    .SYNOPSIS
    Enumerates Azure Cognitive Services accounts (OpenAI, AI Search, Speech, Language,
    Document Intelligence, Content Safety, AI Foundry, etc.) and audits security
    misconfigurations. Optionally extracts API keys.

    .DESCRIPTION
    Iterates across all accessible subscriptions, lists all Cognitive Services accounts
    (provider Microsoft.CognitiveServices/accounts) and Azure AI Search services
    (provider Microsoft.Search/searchServices), and evaluates each against security checks:

      Critical:     PublicNetworkAccessEnabled without firewall rules, API keys extracted
      High:         NoPrivateEndpoint, LocalAuthEnabled (keys active), OutboundNotRestricted,
                    DiagnosticLogsDisabled, NoCustomerManagedKey
      Informational: Kind/SKU, PublicNetworkAccess, RestrictOutboundNetworkAccess

    Covers all Cognitive Services kinds including:
      - Azure OpenAI (kind: OpenAI)
      - Azure AI Search (Microsoft.Search/searchServices)
      - Speech Service (kind: SpeechServices)
      - Language / Text Analytics (kind: TextAnalytics)
      - Document Intelligence / Form Recognizer (kind: FormRecognizer)
      - Content Safety (kind: ContentSafety)
      - Computer Vision (kind: ComputerVision)
      - Azure AI services (kind: CognitiveServices)
      - Bing Search (kind: Bing.Search.v7)

    With -ScanSecrets, calls listKeys (Cognitive Services) or listAdminKeys (AI Search)
    to retrieve API keys in plaintext.

    Required permissions:
      Microsoft.CognitiveServices/accounts/read
      Microsoft.CognitiveServices/accounts/listKeys/action         (for -ScanSecrets)
      Microsoft.Search/searchServices/read
      Microsoft.Search/searchServices/listAdminKeys/action         (for -ScanSecrets)
      microsoft.insights/diagnosticSettings/read                   (optional)

    .PARAMETER AccessToken
    Azure Management API access token. Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where output is saved. Raw dumps under:
      <OutputPath>\CognitiveServicesRawDump\<SubscriptionName>\<AccountName>\account.json
    CSV reports:
      <OutputPath>\AzRA-CognitiveServices_<timestamp>.csv
      <OutputPath>\AzRA-CognitiveServices-Keys_<timestamp>.csv  (only if -ScanSecrets)

    .PARAMETER ScanSecrets
    If specified, retrieves API keys via listKeys (Cognitive Services) or listAdminKeys
    (AI Search). Keys provide full access to the service endpoint.

    .PARAMETER MaxRetries
    Maximum retry attempts. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-CognitiveServices -AccessToken $token

    .EXAMPLE
    Get-AzRA-CognitiveServices -AccessToken $token -ScanSecrets -OutputPath 'C:\Audit'

    .EXAMPLE
    $result = Get-AzRA-CognitiveServices -AccessToken $token -ScanSecrets
    $result | Where-Object { $_.HasKeys } | ForEach-Object {
        Write-Output "=== $($_.AccountName) [$($_.Kind)] ==="
        $_.Keys | Format-Table KeyName, KeyValue
    }

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    One object per Cognitive Services account or AI Search service.
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

    # -- Private helpers -------------------------------------------------------

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
            if ($code -in @(401, 403)) { Write-Warning "    [403] Sin permiso para $Label" }
            else { Write-Verbose "    POST failed ($code): $Uri" }
            return $null
        }
    }

    # -- Inner processing: Cognitive Services account --------------------------

    function Invoke-ProcessCognitiveAccount {
        param($Account, [string]$SubId, [string]$SubName,
              $AllKeys,
              [string]$DumpRoot)

        $accName  = $Account.name
        $rgName   = Get-RgFromId -ResourceId $Account.id
        $props    = $Account.properties
        $kind     = $Account.kind
        $sku      = $Account.sku.name
        $endpoint = $props.endpoint

        Write-Host "    [~] Analizando: $accName [$kind]" -ForegroundColor Gray

        # Security checks
        $pubNetEnabled   = ($props.publicNetworkAccess -ne 'Disabled')
        $ipRules         = @($props.networkAcls.ipRules)
        $vnetRules       = @($props.networkAcls.virtualNetworkRules)
        $noFirewallRules = ($pubNetEnabled -and $ipRules.Count -eq 0 -and $vnetRules.Count -eq 0)
        $privateEps      = @($props.privateEndpointConnections)
        $noPrivateEp     = ($privateEps.Count -eq 0)
        $localAuthDisabled = ($props.disableLocalAuth -eq $true)
        $noCmk           = ($null -eq $props.encryption -or $props.encryption.keySource -ne 'Microsoft.KeyVault')
        $restrictOutbound = ($props.restrictOutboundNetworkAccess -eq $true)

        # Diagnostic settings
        $diagLogsDisabled = $null
        try {
            $diag = Invoke-AzRARequest `
                -Uri "https://management.azure.com/$($Account.id)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview" `
                -AccessToken $AccessToken -Method GET -ErrorAction Stop
            $diagLogsDisabled = ($null -eq $diag -or @($diag).Count -eq 0)
        }
        catch { Write-Verbose "    Sin acceso a diagnostic settings para $accName" }

        # Key extraction
        $keys    = [System.Collections.Generic.List[PSCustomObject]]::new()
        $hasKeys = $false
        $keysRaw = $null

        if ($ScanSecrets -and -not $localAuthDisabled) {
            Write-Host "      [~] Extrayendo API keys..." -ForegroundColor Gray
            $listUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$rgName/providers/Microsoft.CognitiveServices/accounts/$accName/listKeys?api-version=2024-04-01-preview"
            $keysRaw = Invoke-ArmPost -Uri $listUri -Label "CognitiveServices listKeys ($accName)"

            if ($keysRaw) {
                foreach ($pair in @(
                    @{ Name = 'key1'; Value = $keysRaw.key1 },
                    @{ Name = 'key2'; Value = $keysRaw.key2 }
                )) {
                    if ($pair.Value) {
                        $entry = [PSCustomObject]@{
                            SubscriptionName = $SubName
                            SubscriptionId   = $SubId
                            ResourceGroup    = $rgName
                            AccountName      = $accName
                            Kind             = $kind
                            Endpoint         = $endpoint
                            KeyName          = $pair.Name
                            KeyValue         = $pair.Value
                        }
                        $keys.Add($entry)
                        $AllKeys.Add($entry)
                    }
                }
                $hasKeys = ($keys.Count -gt 0)
                Write-Host "      [+] API keys extraidas: $($keys.Count)" -ForegroundColor Red
            }
        }
        elseif ($ScanSecrets -and $localAuthDisabled) {
            Write-Host "      [~] Local auth deshabilitado en $accName - keys no disponibles" -ForegroundColor Gray
        }

        $hasCritical = ($noFirewallRules -or $hasKeys)
        $hasHigh     = ($noCmk -or $noPrivateEp -or (-not $restrictOutbound) -or ($diagLogsDisabled -eq $true))

        if ($hasCritical) {
            Write-Host "    [!] CRITICO: $accName [$kind]" -ForegroundColor Red
            if ($noFirewallRules) { Write-Host "        - NoFirewallRules: acceso publico sin restricciones IP ni VNet" -ForegroundColor Red }
            if ($hasKeys)         { Write-Host "        - API keys extraidas: $($keys.Count) (acceso directo al endpoint)" -ForegroundColor Red }
        }
        elseif ($hasHigh) {
            Write-Host "    [!] ALTO: $accName [$kind]" -ForegroundColor Yellow
            if ($noCmk)                           { Write-Host "        - NoCustomerManagedKey: cifrado con clave de Microsoft" -ForegroundColor Yellow }
            if ($noPrivateEp)                     { Write-Host "        - NoPrivateEndpoint: sin private endpoint configurado" -ForegroundColor Yellow }
            if (-not $restrictOutbound)           { Write-Host "        - OutboundNotRestricted: el servicio puede hacer llamadas salientes a cualquier destino" -ForegroundColor Yellow }
            if ($diagLogsDisabled -eq $true)      { Write-Host "        - DiagnosticLogsDisabled: sin Diagnostic Settings" -ForegroundColor Yellow }
        }
        else { Write-Host "    [OK] $accName [$kind]" -ForegroundColor Green }

        # Raw dump
        $rawFilePath = $null
        if ($DumpRoot -and $rgName) {
            $dir = Join-Path (Join-Path $DumpRoot ($SubName -replace '[^a-zA-Z0-9_\-]','_')) ($accName -replace '[^a-zA-Z0-9_\-]','_')
            if (-not (Test-Path $dir)) { try { New-Item -ItemType Directory -Force -Path $dir -ErrorAction Stop | Out-Null } catch {} }
            if (Test-Path $dir) {
                try { $Account | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $dir 'account.json') -Encoding UTF8 -ErrorAction Stop } catch {}
                if ($keysRaw) { try { $keysRaw | ConvertTo-Json | Set-Content -Path (Join-Path $dir 'keys.json') -Encoding UTF8 -ErrorAction Stop } catch {} }
                $rawFilePath = $dir
            }
        }

        return [PSCustomObject]@{
            SubscriptionId         = $SubId
            SubscriptionName       = $SubName
            ResourceGroup          = $rgName
            AccountName            = $accName
            Kind                   = $kind
            Sku                    = $sku
            Location               = $Account.location
            Endpoint               = $endpoint
            PublicNetworkEnabled   = $pubNetEnabled
            NoFirewallRules        = $noFirewallRules
            NoPrivateEndpoint      = $noPrivateEp
            LocalAuthEnabled       = (-not $localAuthDisabled)
            NoCustomerManagedKey   = $noCmk
            OutboundRestricted     = $restrictOutbound
            DiagnosticLogsDisabled = $diagLogsDisabled
            HasKeys                = $hasKeys
            KeyCount               = $keys.Count
            Keys                   = $keys.ToArray()
            HasCriticalFindings    = $hasCritical
            HasHighFindings        = $hasHigh
            RawFilePath            = $rawFilePath
        }
    }

    # -- Inner processing: AI Search service -----------------------------------

    function Invoke-ProcessSearchService {
        param($Service, [string]$SubId, [string]$SubName,
              $AllKeys,
              [string]$DumpRoot)

        $svcName  = $Service.name
        $rgName   = Get-RgFromId -ResourceId $Service.id
        $props    = $Service.properties
        $sku      = $Service.sku.name
        $endpoint = "https://$svcName.search.windows.net"

        Write-Host "    [~] Analizando: $svcName [AISearch]" -ForegroundColor Gray

        # Security checks
        $pubNetEnabled   = ($props.publicNetworkAccess -ne 'disabled')
        $ipRules         = @($props.networkRuleSet.ipRules)
        $noFirewallRules = ($pubNetEnabled -and $ipRules.Count -eq 0)
        $privateEps      = @($props.privateEndpointConnections)
        $noPrivateEp     = ($privateEps.Count -eq 0)
        $localAuthDisabled = ($props.disableLocalAuth -eq $true)

        # Diagnostic settings
        $diagLogsDisabled = $null
        try {
            $diag = Invoke-AzRARequest `
                -Uri "https://management.azure.com/$($Service.id)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview" `
                -AccessToken $AccessToken -Method GET -ErrorAction Stop
            $diagLogsDisabled = ($null -eq $diag -or @($diag).Count -eq 0)
        }
        catch { Write-Verbose "    Sin acceso a diagnostic settings para $svcName" }

        # Key extraction (AI Search uses listAdminKeys, not listKeys)
        $keys    = [System.Collections.Generic.List[PSCustomObject]]::new()
        $hasKeys = $false
        $keysRaw = $null

        if ($ScanSecrets -and -not $localAuthDisabled) {
            Write-Host "      [~] Extrayendo admin keys (AI Search)..." -ForegroundColor Gray
            $listUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$rgName/providers/Microsoft.Search/searchServices/$svcName/listAdminKeys?api-version=2024-06-01-preview"
            $keysRaw = Invoke-ArmPost -Uri $listUri -Label "AISearch listAdminKeys ($svcName)"

            if ($keysRaw) {
                foreach ($pair in @(
                    @{ Name = 'primaryKey';   Value = $keysRaw.primaryKey },
                    @{ Name = 'secondaryKey'; Value = $keysRaw.secondaryKey }
                )) {
                    if ($pair.Value) {
                        $entry = [PSCustomObject]@{
                            SubscriptionName = $SubName
                            SubscriptionId   = $SubId
                            ResourceGroup    = $rgName
                            AccountName      = $svcName
                            Kind             = 'AISearch'
                            Endpoint         = $endpoint
                            KeyName          = $pair.Name
                            KeyValue         = $pair.Value
                        }
                        $keys.Add($entry)
                        $AllKeys.Add($entry)
                    }
                }
                $hasKeys = ($keys.Count -gt 0)
                Write-Host "      [+] Admin keys extraidas: $($keys.Count)" -ForegroundColor Red
            }
        }
        elseif ($ScanSecrets -and $localAuthDisabled) {
            Write-Host "      [~] Local auth deshabilitado en $svcName - keys no disponibles" -ForegroundColor Gray
        }

        $hasCritical = ($noFirewallRules -or $hasKeys)
        $hasHigh     = ($noPrivateEp -or (-not $localAuthDisabled) -or ($diagLogsDisabled -eq $true))

        if ($hasCritical) {
            Write-Host "    [!] CRITICO: $svcName [AISearch]" -ForegroundColor Red
            if ($noFirewallRules) { Write-Host "        - NoFirewallRules: acceso publico sin restricciones IP" -ForegroundColor Red }
            if ($hasKeys)         { Write-Host "        - Admin keys extraidas: $($keys.Count) (acceso total al indice de busqueda)" -ForegroundColor Red }
        }
        elseif ($hasHigh) {
            Write-Host "    [!] ALTO: $svcName [AISearch]" -ForegroundColor Yellow
            if ($noPrivateEp)               { Write-Host "        - NoPrivateEndpoint: sin private endpoint" -ForegroundColor Yellow }
            if (-not $localAuthDisabled)    { Write-Host "        - LocalAuthEnabled: admin keys activas" -ForegroundColor Yellow }
            if ($diagLogsDisabled -eq $true){ Write-Host "        - DiagnosticLogsDisabled: sin Diagnostic Settings" -ForegroundColor Yellow }
        }
        else { Write-Host "    [OK] $svcName [AISearch]" -ForegroundColor Green }

        # Raw dump
        $rawFilePath = $null
        if ($DumpRoot -and $rgName) {
            $dir = Join-Path (Join-Path $DumpRoot ($SubName -replace '[^a-zA-Z0-9_\-]','_')) ($svcName -replace '[^a-zA-Z0-9_\-]','_')
            if (-not (Test-Path $dir)) { try { New-Item -ItemType Directory -Force -Path $dir -ErrorAction Stop | Out-Null } catch {} }
            if (Test-Path $dir) {
                try { $Service | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $dir 'service.json') -Encoding UTF8 -ErrorAction Stop } catch {}
                if ($keysRaw) { try { $keysRaw | ConvertTo-Json | Set-Content -Path (Join-Path $dir 'adminKeys.json') -Encoding UTF8 -ErrorAction Stop } catch {} }
                $rawFilePath = $dir
            }
        }

        return [PSCustomObject]@{
            SubscriptionId         = $SubId
            SubscriptionName       = $SubName
            ResourceGroup          = $rgName
            AccountName            = $svcName
            Kind                   = 'AISearch'
            Sku                    = $sku
            Location               = $Service.location
            Endpoint               = $endpoint
            PublicNetworkEnabled   = $pubNetEnabled
            NoFirewallRules        = $noFirewallRules
            NoPrivateEndpoint      = $noPrivateEp
            LocalAuthEnabled       = (-not $localAuthDisabled)
            NoCustomerManagedKey   = $true   # Search CMK only on Standard/higher tiers
            OutboundRestricted     = $null
            DiagnosticLogsDisabled = $diagLogsDisabled
            HasKeys                = $hasKeys
            KeyCount               = $keys.Count
            Keys                   = $keys.ToArray()
            HasCriticalFindings    = $hasCritical
            HasHighFindings        = $hasHigh
            RawFilePath            = $rawFilePath
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
            $dumpRoot = Join-Path $OutputPath 'CognitiveServicesRawDump'
            if (-not (Test-Path $dumpRoot)) { New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null }
        }
        catch { throw "Cannot create output directory '$OutputPath': $_" }
    }

    Write-Host ""
    Write-Host "[*] Cognitive Services / AI Services - iniciando auditoria..." -ForegroundColor Cyan

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

        # Cognitive Services accounts
        Write-Host "    [~] Enumerando Cognitive Services / AI accounts..." -ForegroundColor Gray

        $csAccounts = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.CognitiveServices/accounts?api-version=2024-04-01-preview" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if ($csAccounts) {
            Write-Host "    [+] Cognitive Services accounts: $(@($csAccounts).Count)" -ForegroundColor White

            foreach ($account in $csAccounts) {
                $result = Invoke-ProcessCognitiveAccount `
                    -Account $account -SubId $subId -SubName $subName `
                    -AllKeys $allKeys -DumpRoot $dumpRoot
                if ($result) { $allAccounts.Add($result) }
            }
        }
        else {
            Write-Host "    [~] Sin Cognitive Services accounts en esta subscripcion" -ForegroundColor Gray
        }

        # AI Search services
        Write-Host "    [~] Enumerando Azure AI Search services..." -ForegroundColor Gray

        $searchServices = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Search/searchServices?api-version=2024-06-01-preview" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if ($searchServices) {
            Write-Host "    [+] AI Search services: $(@($searchServices).Count)" -ForegroundColor White

            foreach ($svc in $searchServices) {
                $result = Invoke-ProcessSearchService `
                    -Service $svc -SubId $subId -SubName $subName `
                    -AllKeys $allKeys -DumpRoot $dumpRoot
                if ($result) { $allAccounts.Add($result) }
            }
        }
        else {
            Write-Host "    [~] Sin AI Search services en esta subscripcion" -ForegroundColor Gray
        }
    }

    # -- Export CSVs -----------------------------------------------------------

    if ($OutputPath -and $allAccounts.Count -gt 0) {
        try {
            $allAccounts.ToArray() | Select-Object SubscriptionName, ResourceGroup,
                AccountName, Kind, Sku, Location, Endpoint,
                PublicNetworkEnabled, NoFirewallRules, NoPrivateEndpoint,
                LocalAuthEnabled, NoCustomerManagedKey, DiagnosticLogsDisabled,
                HasKeys, KeyCount,
                HasCriticalFindings, HasHighFindings, RawFilePath |
                Export-Csv -Path (Join-Path $OutputPath "AzRA-CognitiveServices_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        }
        catch { Write-Warning "Could not export CognitiveServices CSV: $_" }

        if ($ScanSecrets -and $allKeys.Count -gt 0) {
            try {
                $allKeys.ToArray() | Export-Csv `
                    -Path (Join-Path $OutputPath "AzRA-CognitiveServices-Keys_$timestamp.csv") `
                    -NoTypeInformation -Encoding UTF8
            }
            catch { Write-Warning "Could not export keys CSV: $_" }
        }
    }

    # -- Summary ---------------------------------------------------------------

    $critCount  = ($allAccounts | Where-Object { $_.HasCriticalFindings }).Count
    $highCount  = ($allAccounts | Where-Object { $_.HasHighFindings -and -not $_.HasCriticalFindings }).Count
    $totalCount = $allAccounts.Count

    Write-Host ""
    Write-Host "[*] Auditoria completada: $totalCount servicios AI/Cognitive analizados" -ForegroundColor Cyan
    if ($critCount -gt 0) {
        Write-Host "  [!] Servicios con hallazgos CRITICOS: $critCount" -ForegroundColor Red
        $allAccounts | Where-Object { $_.HasCriticalFindings } | ForEach-Object {
            $flags = @()
            if ($_.NoFirewallRules)  { $flags += 'SinFirewall' }
            if ($_.LocalAuthEnabled) { $flags += 'KeysActivas' }
            if ($_.HasKeys)          { $flags += "$($_.KeyCount) keys" }
            Write-Host "    - $($_.AccountName) [$($_.Kind)]: $($flags -join ', ')" -ForegroundColor Red
        }
    }
    if ($highCount -gt 0) { Write-Host "  [!] Servicios con hallazgos ALTOS: $highCount" -ForegroundColor Yellow }
    if ($ScanSecrets) {
        $accsWithKeys = ($allAccounts | Where-Object { $_.HasKeys }).Count
        Write-Host "  [+] API keys extraidas de $accsWithKeys servicios ($($allKeys.Count) keys total)" -ForegroundColor White
    }
    if ($OutputPath) { Write-Host "  [+] Resultados exportados en: $OutputPath" -ForegroundColor White }
    Write-Host ""

    return $allAccounts.ToArray()
}
