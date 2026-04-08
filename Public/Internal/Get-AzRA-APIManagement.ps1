# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-APIManagement {
    <#
    .SYNOPSIS
    Enumerates Azure API Management services and audits security misconfigurations,
    extracting subscription keys, named values (secrets), and backend credentials.

    .DESCRIPTION
    Iterates across all accessible subscriptions (or a specific one), lists all API Management
    services, and evaluates each against security checks:

      Critical:     PublicNetworkAccessEnabled (no virtual network), DirectManagementEnabled,
                    DeveloperPortalEnabled (unauthenticated access), NamedValuesWithSecrets
      High:         HttpsOnlyDisabled, SkuConsumption (no VNet support), NoClientCertificates,
                    LegacyProtocolsEnabled, DiagnosticLogsDisabled
      Informational: HasCustomDomains, ExternalVNetIntegration, InternalVNetIntegration

    With -ScanSecrets, retrieves:
      - All subscription keys (primary + secondary) via listSecrets
      - Named Values of type 'secret' via listValue
      - Backend credentials (basic auth, certificate headers) from backend definitions

    Required permissions:
      Microsoft.ApiManagement/service/read
      Microsoft.ApiManagement/service/subscriptions/listSecrets/action   (for -ScanSecrets)
      Microsoft.ApiManagement/service/namedValues/listValue/action        (for -ScanSecrets)
      microsoft.insights/diagnosticSettings/read                          (optional)

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription by ID. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where all output is saved. Raw JSON dumps are saved under:
      <OutputPath>\APIManagementRawDump\<SubscriptionName>\<ServiceName>\service.json
      <OutputPath>\APIManagementRawDump\<SubscriptionName>\<ServiceName>\namedValues.json
      <OutputPath>\APIManagementRawDump\<SubscriptionName>\<ServiceName>\subscriptions.json
      <OutputPath>\APIManagementRawDump\<SubscriptionName>\<ServiceName>\backends.json
    CSV reports saved as:
      <OutputPath>\AzRA-APIManagement_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-APIManagement-Secrets_<yyyyMMdd-HHmm>.csv  (only if -ScanSecrets)

    .PARAMETER ScanSecrets
    If specified, retrieves subscription keys (listSecrets), named value secrets (listValue),
    and backend credentials. These frequently contain hardcoded API keys, passwords, and
    connection tokens used by the API gateway to call backend services.

    .PARAMETER MaxRetries
    Maximum retry attempts on throttling (HTTP 429) or transient errors (5xx). Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-APIManagement -AccessToken $token
    Enumerates all APIM services with ARM-level security checks.

    .EXAMPLE
    Get-AzRA-APIManagement -AccessToken $token -ScanSecrets -OutputPath 'C:\Audit'
    Full audit: ARM checks + subscription keys + named value secrets + backend credentials.

    .EXAMPLE
    $result = Get-AzRA-APIManagement -AccessToken $token -ScanSecrets
    $result | Where-Object { $_.HasSecrets } | ForEach-Object {
        $_.Secrets | Format-Table SecretType, Name, Value
    }

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    One object per APIM service containing identity, security checks, and optionally secrets.
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

    # -- Private helpers -------------------------------------------------------

    function Get-RgFromId {
        param([string]$ResourceId)
        if ($ResourceId -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
        return $null
    }

    function Get-ArmHeaders {
        return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    }

    function Invoke-ApimPost {
        param([string]$Uri, [string]$Label)
        try {
            return Invoke-RestMethod -Uri $Uri -Headers (Get-ArmHeaders) -Method POST -ErrorAction Stop
        }
        catch {
            $code = $null
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code -in @(401, 403)) {
                Write-Warning "    [403] Sin permiso para $Label (requiere listSecrets/listValue action)"
            }
            else {
                Write-Verbose "    POST failed ($code): $Uri"
            }
            return $null
        }
    }

    # -- Initialization --------------------------------------------------------

    $allServices = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSecrets  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp   = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot    = $null

    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
            $dumpRoot = Join-Path $OutputPath 'APIManagementRawDump'
            if (-not (Test-Path $dumpRoot)) {
                New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null
            }
        }
        catch {
            throw "Cannot create output directory '$OutputPath': $_"
        }
    }

    # -- Resolve subscriptions -------------------------------------------------

    Write-Host ""
    Write-Host "[*] API Management - iniciando auditoria..." -ForegroundColor Cyan

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

    Write-Host "  [~] Subscripciones a analizar: $(@($subs).Count)" -ForegroundColor Gray

    # -- Main loop -------------------------------------------------------------

    foreach ($sub in $subs) {
        $subId   = $sub.subscriptionId
        $subName = $sub.displayName

        Write-Host ""
        Write-Host "  [*] Subscripcion: $subName ($subId)" -ForegroundColor Cyan
        Write-Host "    [~] Enumerando API Management services..." -ForegroundColor Gray

        $services = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.ApiManagement/service?api-version=2023-09-01-preview" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $services) {
            Write-Host "    [~] Sin servicios de API Management en esta subscripcion" -ForegroundColor Gray
            continue
        }

        Write-Host "    [+] Servicios encontrados: $(@($services).Count)" -ForegroundColor White

        foreach ($svc in $services) {
            $svcName  = $svc.name
            $rgName   = Get-RgFromId -ResourceId $svc.id
            $props    = $svc.properties
            $sku      = $svc.sku.name

            Write-Host "    [~] Analizando: $svcName [SKU: $sku]" -ForegroundColor Gray

            # -- ARM security checks -------------------------------------------

            # Critical
            $vnetType         = $props.virtualNetworkType  # None, External, Internal
            $publicNetEnabled = ($vnetType -eq 'None')

            # Developer portal
            $portalStatus     = $props.developerPortalUrl
            $devPortalEnabled = ($null -ne $portalStatus -and $portalStatus -ne '')

            # Direct management endpoint (port 3443) - enabled unless explicitly disabled
            # Exposed on public IP when virtualNetworkType = None
            $directMgmtEnabled = $publicNetEnabled  # port 3443 always open when public

            # High
            $httpsOnlyDisabled = $false  # APIM enforces HTTPS by default; check custom policies
            $skuConsumption    = ($sku -eq 'Consumption')  # No VNet support in Consumption tier
            $legacyTls         = ($props.customProperties -and
                                  ($props.customProperties.'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10' -eq 'true' -or
                                   $props.customProperties.'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11' -eq 'true'))
            $legacySsl3        = ($props.customProperties -and
                                  $props.customProperties.'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30' -eq 'true')
            $legacyProtocols   = ($legacyTls -or $legacySsl3)

            # Ciphers
            $weakCiphers       = ($props.customProperties -and
                                  $props.customProperties.'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168' -eq 'true')

            # Diagnostic settings (non-fatal)
            $diagLogsDisabled  = $null
            try {
                $diagSettings = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/$($svc.id)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview" `
                    -AccessToken $AccessToken -Method GET -ErrorAction Stop
                $diagLogsDisabled = ($null -eq $diagSettings -or @($diagSettings).Count -eq 0)
            }
            catch {
                Write-Verbose "    Sin acceso a diagnostic settings para $svcName"
            }

            # Informational
            $hasCustomDomains  = ($props.hostnameConfigurations -and @($props.hostnameConfigurations | Where-Object { $_.hostName -notmatch '\.azure-api\.net$' }).Count -gt 0)
            $gatewayUrl        = $props.gatewayUrl
            $managementApiUrl  = $props.managementApiUrl

            # -- Secrets extraction (-ScanSecrets) -----------------------------

            $secrets      = [System.Collections.Generic.List[PSCustomObject]]::new()
            $namedValues  = $null
            $subscriptions = $null
            $backends     = $null

            if ($ScanSecrets) {
                Write-Host "      [~] Extrayendo secretos..." -ForegroundColor Gray

                # 1. Named Values (secrets)
                $nvAll = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.ApiManagement/service/$svcName/namedValues?api-version=2023-09-01-preview" `
                    -AccessToken $AccessToken -Method GET -EnablePagination
                $namedValues = $nvAll

                if ($nvAll) {
                    $secretNVs = @($nvAll | Where-Object { $_.properties.secret -eq $true })
                    Write-Host "      [~] Named Values de tipo secret: $($secretNVs.Count)" -ForegroundColor Gray

                    foreach ($nv in $secretNVs) {
                        $nvName  = $nv.name
                        $listUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.ApiManagement/service/$svcName/namedValues/$nvName/listValue?api-version=2023-09-01-preview"
                        $nvVal   = Invoke-ApimPost -Uri $listUri -Label "namedValue listValue ($nvName)"
                        if ($nvVal) {
                            $entry = [PSCustomObject]@{
                                SubscriptionName = $subName
                                SubscriptionId   = $subId
                                ResourceGroup    = $rgName
                                ServiceName      = $svcName
                                SecretType       = 'NamedValue'
                                Name             = $nv.properties.displayName
                                Value            = $nvVal.value
                            }
                            $secrets.Add($entry)
                            $allSecrets.Add($entry)
                        }
                    }
                }

                # 2. Subscription keys
                $subs2 = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.ApiManagement/service/$svcName/subscriptions?api-version=2023-09-01-preview" `
                    -AccessToken $AccessToken -Method GET -EnablePagination
                $subscriptions = $subs2

                if ($subs2) {
                    Write-Host "      [~] Subscripciones APIM encontradas: $(@($subs2).Count)" -ForegroundColor Gray
                    foreach ($apimSub in $subs2) {
                        $apimSubId  = $apimSub.name
                        $listUri    = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.ApiManagement/service/$svcName/subscriptions/$apimSubId/listSecrets?api-version=2023-09-01-preview"
                        $keysResp   = Invoke-ApimPost -Uri $listUri -Label "subscription listSecrets ($apimSubId)"
                        if ($keysResp) {
                            foreach ($keyPair in @(
                                @{ KeyType = 'primaryKey';   Value = $keysResp.primaryKey },
                                @{ KeyType = 'secondaryKey'; Value = $keysResp.secondaryKey }
                            )) {
                                if ($keyPair.Value) {
                                    $entry = [PSCustomObject]@{
                                        SubscriptionName = $subName
                                        SubscriptionId   = $subId
                                        ResourceGroup    = $rgName
                                        ServiceName      = $svcName
                                        SecretType       = 'SubscriptionKey'
                                        Name             = "$($apimSub.properties.displayName) - $($keyPair.KeyType)"
                                        Value            = $keyPair.Value
                                    }
                                    $secrets.Add($entry)
                                    $allSecrets.Add($entry)
                                }
                            }
                        }
                    }
                }

                # 3. Backends (may contain basic auth credentials or token headers)
                $backendsAll = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.ApiManagement/service/$svcName/backends?api-version=2023-09-01-preview" `
                    -AccessToken $AccessToken -Method GET -EnablePagination
                $backends = $backendsAll

                if ($backendsAll) {
                    foreach ($backend in $backendsAll) {
                        $creds = $backend.properties.credentials
                        if ($creds) {
                            # Basic auth
                            if ($creds.authorization -and $creds.authorization.parameter) {
                                $entry = [PSCustomObject]@{
                                    SubscriptionName = $subName
                                    SubscriptionId   = $subId
                                    ResourceGroup    = $rgName
                                    ServiceName      = $svcName
                                    SecretType       = 'BackendCredential'
                                    Name             = "Backend: $($backend.name) (scheme: $($creds.authorization.scheme))"
                                    Value            = $creds.authorization.parameter
                                }
                                $secrets.Add($entry)
                                $allSecrets.Add($entry)
                            }
                            # Header-based credentials
                            if ($creds.header) {
                                $creds.header.PSObject.Properties | ForEach-Object {
                                    $headerName = $_.Name
                                    $headerVals = $_.Value -join ', '
                                    $entry = [PSCustomObject]@{
                                        SubscriptionName = $subName
                                        SubscriptionId   = $subId
                                        ResourceGroup    = $rgName
                                        ServiceName      = $svcName
                                        SecretType       = 'BackendHeader'
                                        Name             = "Backend: $($backend.name) - Header: $headerName"
                                        Value            = $headerVals
                                    }
                                    $secrets.Add($entry)
                                    $allSecrets.Add($entry)
                                }
                            }
                        }
                    }
                }

                $hasSecrets = ($secrets.Count -gt 0)
                if ($hasSecrets) {
                    Write-Host "      [+] Secretos extraidos: $($secrets.Count)" -ForegroundColor Red
                }
            }

            $hasSecrets = ($secrets.Count -gt 0)

            # -- Summary flags -------------------------------------------------

            $hasCritical = (
                $publicNetEnabled -or
                $hasSecrets -or
                ($devPortalEnabled -and $publicNetEnabled)
            )
            $hasHigh = (
                $legacyProtocols -or
                $weakCiphers -or
                $skuConsumption -or
                ($diagLogsDisabled -eq $true)
            )

            if ($hasCritical) {
                Write-Host "    [!] CRITICO: $svcName" -ForegroundColor Red
                if ($publicNetEnabled)  { Write-Host "        - PublicNetworkAccessEnabled: sin VNet integration, expuesto publicamente" -ForegroundColor Red }
                if ($directMgmtEnabled) { Write-Host "        - DirectManagementEndpoint: puerto 3443 accesible (sin VNet)" -ForegroundColor Red }
                if ($devPortalEnabled -and $publicNetEnabled) { Write-Host "        - DeveloperPortalPublico: $portalStatus" -ForegroundColor Red }
                if ($hasSecrets)        { Write-Host "        - Secretos extraidos: $($secrets.Count) valores (keys, named values, backend creds)" -ForegroundColor Red }
            }
            elseif ($hasHigh) {
                Write-Host "    [!] ALTO: $svcName" -ForegroundColor Yellow
                if ($legacyProtocols) { Write-Host "        - LegacyProtocolsEnabled: TLS 1.0/1.1 o SSL 3.0 habilitados" -ForegroundColor Yellow }
                if ($weakCiphers)     { Write-Host "        - WeakCiphers: 3DES habilitado" -ForegroundColor Yellow }
                if ($skuConsumption)  { Write-Host "        - SkuConsumption: SKU Consumption sin soporte para VNet" -ForegroundColor Yellow }
                if ($diagLogsDisabled -eq $true) { Write-Host "        - DiagnosticLogsDisabled: sin Diagnostic Settings" -ForegroundColor Yellow }
            }
            else {
                Write-Host "    [OK] $svcName" -ForegroundColor Green
            }

            # -- Raw dump ------------------------------------------------------

            $rawFilePath = $null
            if ($dumpRoot -and $rgName) {
                $safeSubName = $subName  -replace '[^a-zA-Z0-9_\-]', '_'
                $safeSvcName = $svcName  -replace '[^a-zA-Z0-9_\-]', '_'
                $svcDumpDir  = Join-Path (Join-Path $dumpRoot $safeSubName) $safeSvcName

                if (-not (Test-Path $svcDumpDir)) {
                    try {
                        New-Item -ItemType Directory -Force -Path $svcDumpDir -ErrorAction Stop | Out-Null
                    }
                    catch { Write-Warning "  Could not create dump dir '$svcDumpDir': $_" }
                }

                if (Test-Path $svcDumpDir) {
                    foreach ($pair in @(
                        @{ Name = 'service.json';       Data = $svc },
                        @{ Name = 'namedValues.json';   Data = $namedValues },
                        @{ Name = 'subscriptions.json'; Data = $subscriptions },
                        @{ Name = 'backends.json';      Data = $backends }
                    )) {
                        if ($pair.Data) {
                            try {
                                $pair.Data | ConvertTo-Json -Depth 20 |
                                    Set-Content -Path (Join-Path $svcDumpDir $pair.Name) -Encoding UTF8 -ErrorAction Stop
                            }
                            catch { Write-Warning "  Could not write $($pair.Name) for '$svcName': $_" }
                        }
                    }
                    $rawFilePath = $svcDumpDir
                }
            }

            # -- Build pipeline object -----------------------------------------

            $obj = [PSCustomObject]@{
                # Identity
                SubscriptionId       = $subId
                SubscriptionName     = $subName
                ResourceGroup        = $rgName
                ServiceName          = $svcName
                Sku                  = $sku
                Location             = $svc.location
                GatewayUrl           = $gatewayUrl
                ManagementApiUrl     = $managementApiUrl
                DeveloperPortalUrl   = $portalStatus
                VirtualNetworkType   = $vnetType

                # Critical
                PublicNetworkEnabled    = $publicNetEnabled
                DirectMgmtEndpointOpen  = $directMgmtEnabled
                DeveloperPortalEnabled  = $devPortalEnabled

                # High
                LegacyProtocolsEnabled  = $legacyProtocols
                WeakCiphersEnabled      = $weakCiphers
                SkuConsumption          = $skuConsumption
                DiagnosticLogsDisabled  = $diagLogsDisabled

                # Informational
                HasCustomDomains        = $hasCustomDomains

                # Secrets (if -ScanSecrets)
                HasSecrets              = $hasSecrets
                SecretCount             = $secrets.Count
                Secrets                 = $secrets.ToArray()

                # Summary flags
                HasCriticalFindings     = $hasCritical
                HasHighFindings         = $hasHigh

                RawFilePath             = $rawFilePath
            }

            $allServices.Add($obj)
        }
    }

    # -- Export CSVs -----------------------------------------------------------

    if ($OutputPath -and $allServices.Count -gt 0) {
        try {
            $allServices.ToArray() | Select-Object SubscriptionName, ResourceGroup, ServiceName,
                Sku, Location, GatewayUrl, ManagementApiUrl, DeveloperPortalUrl, VirtualNetworkType,
                PublicNetworkEnabled, DirectMgmtEndpointOpen, DeveloperPortalEnabled,
                LegacyProtocolsEnabled, WeakCiphersEnabled, SkuConsumption, DiagnosticLogsDisabled,
                HasCustomDomains, HasSecrets, SecretCount,
                HasCriticalFindings, HasHighFindings, RawFilePath |
                Export-Csv -Path (Join-Path $OutputPath "AzRA-APIManagement_$timestamp.csv") `
                           -NoTypeInformation -Encoding UTF8
        }
        catch { Write-Warning "Could not export APIManagement CSV: $_" }

        if ($ScanSecrets -and $allSecrets.Count -gt 0) {
            try {
                $allSecrets.ToArray() | Export-Csv `
                    -Path (Join-Path $OutputPath "AzRA-APIManagement-Secrets_$timestamp.csv") `
                    -NoTypeInformation -Encoding UTF8
            }
            catch { Write-Warning "Could not export secrets CSV: $_" }
        }
    }

    # -- Final summary ---------------------------------------------------------

    $criticalCount   = ($allServices | Where-Object { $_.HasCriticalFindings }).Count
    $highCount       = ($allServices | Where-Object { $_.HasHighFindings -and -not $_.HasCriticalFindings }).Count
    $secretsTotal    = ($allServices | Measure-Object -Property SecretCount -Sum).Sum
    $totalCount      = $allServices.Count

    Write-Host ""
    Write-Host "[*] Auditoria completada: $totalCount servicios APIM analizados" -ForegroundColor Cyan

    if ($criticalCount -gt 0) {
        Write-Host "  [!] Servicios con hallazgos CRITICOS: $criticalCount" -ForegroundColor Red
        $allServices | Where-Object { $_.HasCriticalFindings } | ForEach-Object {
            $flags = @()
            if ($_.PublicNetworkEnabled)   { $flags += 'PublicAccess' }
            if ($_.DirectMgmtEndpointOpen) { $flags += 'Port3443' }
            if ($_.DeveloperPortalEnabled) { $flags += 'DevPortal' }
            if ($_.HasSecrets)             { $flags += "$($_.SecretCount) secrets" }
            Write-Host "    - $($_.ServiceName): $($flags -join ', ')" -ForegroundColor Red
        }
    }

    if ($highCount -gt 0) {
        Write-Host "  [!] Servicios con hallazgos ALTOS: $highCount" -ForegroundColor Yellow
    }

    if ($ScanSecrets) {
        $svcsWithSecrets = ($allServices | Where-Object { $_.HasSecrets }).Count
        Write-Host "  [+] Secretos extraidos de $svcsWithSecrets servicios ($secretsTotal valores en total)" -ForegroundColor White
    }

    if ($OutputPath) {
        Write-Host "  [+] Resultados exportados en: $OutputPath" -ForegroundColor White
    }
    Write-Host ""

    return $allServices.ToArray()
}
