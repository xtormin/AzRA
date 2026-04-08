# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-FunctionApps {
    <#
    .SYNOPSIS
    Enumerates Azure Function Apps and App Services, auditing security misconfigurations
    and optionally extracting application settings (secrets in plaintext).

    .DESCRIPTION
    Iterates across all accessible subscriptions (or a specific one), lists all Function Apps
    and Web Apps (App Services), and evaluates each against security checks:

      Critical:     AppSettingsExposed (via listSecrets), AuthDisabled, HttpsOnlyDisabled,
                    ClientCertDisabled (when auth is off), PublicSCMAccess
      High:         ManagedIdentityWithBroadRoles, MinTlsWeak, FtpStateEnabled,
                    RemoteDebuggingEnabled, Http20Disabled, AlwaysOnDisabled (Functions)
      Informational: HasStagingSlots, LinuxRuntime, NoVNetIntegration, NoPrivateEndpoint

    With -ScanSecrets, calls the listSecrets/config/appsettings ARM endpoint to retrieve
    all application settings in plaintext. This frequently contains connection strings,
    storage keys, client secrets, API keys, and other credentials.

    Required permissions:
      Microsoft.Web/sites/read
      Microsoft.Web/sites/config/list/action   (only for -ScanSecrets)
      Microsoft.Web/sites/slots/read            (for staging slots)

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription by ID. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where all output is saved. Raw JSON dumps are saved under:
      <OutputPath>\FunctionAppsRawDump\<SubscriptionName>\<AppName>\app.json
      <OutputPath>\FunctionAppsRawDump\<SubscriptionName>\<AppName>\appsettings.json
      <OutputPath>\FunctionAppsRawDump\<SubscriptionName>\<AppName>\slots.json
    CSV reports saved as:
      <OutputPath>\AzRA-FunctionApps_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-FunctionApps-Secrets_<yyyyMMdd-HHmm>.csv  (only if -ScanSecrets)

    .PARAMETER ScanSecrets
    If specified, calls the ARM listSecrets endpoint to retrieve application settings in
    plaintext. This is the primary value of this function from a pentesting perspective.
    Exports results to a separate secrets CSV when -OutputPath is also set.

    .PARAMETER IncludeSlots
    If specified, also enumerates staging slots and optionally retrieves their app settings.
    Slots often share the same secrets as production without the same network controls.

    .PARAMETER MaxRetries
    Maximum retry attempts on throttling (HTTP 429) or transient errors (5xx). Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-FunctionApps -AccessToken $token
    Enumerates all Function Apps and App Services with ARM-level security checks.

    .EXAMPLE
    Get-AzRA-FunctionApps -AccessToken $token -ScanSecrets -OutputPath 'C:\Audit'
    Full audit with app settings extraction to plaintext CSV.

    .EXAMPLE
    Get-AzRA-FunctionApps -AccessToken $token -ScanSecrets -IncludeSlots -OutputPath 'C:\Audit'
    Full audit including staging slots (high value - often same secrets, fewer controls).

    .EXAMPLE
    $result = Get-AzRA-FunctionApps -AccessToken $token -ScanSecrets
    $result | Where-Object { $_.HasSecrets } | ForEach-Object {
        Write-Output "=== $($_.AppName) ==="
        $_.Secrets | ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }
    }
    Display all extracted app settings per app.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    One object per app containing identity fields, boolean security checks, and optionally
    extracted application settings.
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
        [switch]$IncludeSlots,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySec = 5
    )

    # -- EOL runtime version table (as of 2026) --------------------------------
    # Format: 'STACK|MAJOR.MINOR' or 'STACK|MAJOR' -> $true = EOL/unsupported
    $EolRuntimes = @{
        # Python
        'PYTHON|3.6'  = $true; 'PYTHON|3.7'  = $true; 'PYTHON|3.8'  = $true; 'PYTHON|3.9'  = $true
        # Node
        'NODE|12'     = $true; 'NODE|14'     = $true; 'NODE|16'     = $true; 'NODE|18'     = $true
        # PHP
        'PHP|7.2'     = $true; 'PHP|7.3'     = $true; 'PHP|7.4'     = $true
        'PHP|8.0'     = $true; 'PHP|8.1'     = $true
        # .NET / DOTNET
        'DOTNET|3'    = $true; 'DOTNET|5'    = $true; 'DOTNET|6'    = $true; 'DOTNET|7'    = $true
        'DOTNETCORE|1' = $true; 'DOTNETCORE|2' = $true; 'DOTNETCORE|3' = $true
        # Java
        'JAVA|7'      = $true; 'JAVA|8'      = $true
        # PowerShell
        'POWERSHELL|7.0' = $true; 'POWERSHELL|7.2' = $true
    }

    # -- Private helpers -------------------------------------------------------

    function Get-RgFromId {
        param([string]$ResourceId)
        if ($ResourceId -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
        return $null
    }

    function Get-ArmHeaders {
        return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    }

    # Calls ARM POST listSecrets endpoint; returns parsed properties or $null on 403
    function Invoke-ListSecrets {
        param([string]$Uri)
        try {
            $resp = Invoke-RestMethod -Uri $Uri -Headers (Get-ArmHeaders) -Method POST -ErrorAction Stop
            return $resp
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            if ($statusCode -eq 403 -or $statusCode -eq 401) {
                Write-Warning "    [403] Sin permiso para listSecrets: $Uri (requiere Microsoft.Web/sites/config/list/action)"
            }
            else {
                Write-Verbose "    listSecrets failed ($statusCode): $Uri"
            }
            return $null
        }
    }

    # -- Initialization --------------------------------------------------------

    $allApps    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSecrets = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp  = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot   = $null

    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
            $dumpRoot = Join-Path $OutputPath 'FunctionAppsRawDump'
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
    Write-Host "[*] Function Apps / App Services - iniciando auditoria..." -ForegroundColor Cyan

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
        Write-Host "    [~] Enumerando Function Apps y App Services..." -ForegroundColor Gray

        # List all web apps (includes function apps, web apps, api apps)
        $apps = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Web/sites?api-version=2023-12-01" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $apps) {
            Write-Host "    [~] Sin Function Apps ni App Services en esta subscripcion" -ForegroundColor Gray
            continue
        }

        Write-Host "    [+] Apps encontradas: $(@($apps).Count)" -ForegroundColor White

        foreach ($app in $apps) {
            $appName  = $app.name
            $rgName   = Get-RgFromId -ResourceId $app.id
            $props    = $app.properties
            $kind     = $app.kind  # functionapp, app, api, etc.
            $isFuncApp = ($kind -match 'functionapp')

            Write-Host "    [~] Analizando: $appName [$kind]" -ForegroundColor Gray

            # -- ARM security checks -------------------------------------------

            # Critical
            $httpsOnlyDisabled = ($props.httpsOnly -ne $true)
            $authDisabled      = $false  # refined below via auth settings
            $publicScmAccess   = $false  # refined below

            # Get site config for detailed checks (non-fatal)
            $siteConfig = $null
            try {
                $siteConfig = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Web/sites/$appName/config/web?api-version=2023-12-01" `
                    -AccessToken $AccessToken -Method GET -ErrorAction Stop
            }
            catch {
                Write-Verbose "    Could not retrieve site config for $appName"
            }

            $minTlsWeak          = $false
            $ftpEnabled          = $false
            $remoteDebugging     = $false
            $alwaysOnDisabled    = $false
            $clientCertDisabled  = $false
            $basicAuthScmEnabled = $null
            $basicAuthFtpEnabled = $null
            $runtimeEol          = $false
            $runtimeVersion      = $null

            if ($siteConfig) {
                $cfg = $siteConfig.properties
                $minTlsWeak      = ($cfg.minTlsVersion -in @('1.0', '1.1'))
                $ftpEnabled      = ($cfg.ftpsState -notin @('Disabled', 'FtpsOnly'))
                $remoteDebugging = ($cfg.remoteDebuggingEnabled -eq $true)

                $alwaysOnDisabled = ($isFuncApp -and $cfg.alwaysOn -ne $true)
                $clientCertDisabled = ($props.clientCertEnabled -ne $true)

                # SCM (Kudu) access restrictions
                $scmRestrictions = $cfg.scmIpSecurityRestrictions
                $publicScmAccess = ($null -eq $scmRestrictions -or @($scmRestrictions).Count -eq 0 -or
                    ($scmRestrictions | Where-Object { $_.ipAddress -eq 'Any' -and $_.action -eq 'Allow' }).Count -gt 0)

                # Runtime version (linuxFxVersion = "PYTHON|3.9", windowsFxVersion = "dotnet|6")
                $rawRuntime = if ($cfg.linuxFxVersion -and $cfg.linuxFxVersion -ne '') {
                    $cfg.linuxFxVersion
                } elseif ($cfg.windowsFxVersion -and $cfg.windowsFxVersion -ne '') {
                    $cfg.windowsFxVersion
                } else { $null }

                if ($rawRuntime) {
                    $runtimeVersion = $rawRuntime
                    # Normalize: "PYTHON|3.9.1" -> key "PYTHON|3.9", "DOTNET|6.0" -> "DOTNET|6"
                    if ($rawRuntime -match '^([^|]+)\|(\d+)\.?(\d*)') {
                        $stack = $Matches[1].ToUpper()
                        $major = $Matches[2]
                        $minor = $Matches[3]
                        $keyFull  = if ($minor -ne '') { "$stack|$major.$minor" } else { "$stack|$major" }
                        $keyMajor = "$stack|$major"
                        $runtimeEol = ($EolRuntimes[$keyFull] -eq $true -or $EolRuntimes[$keyMajor] -eq $true)
                    }
                }
            }

            # Basic auth (publishing credentials) — separate ARM endpoints
            try {
                $scmPolicy = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Web/sites/$appName/basicPublishingCredentialsPolicies/scm?api-version=2023-12-01" `
                    -AccessToken $AccessToken -Method GET -ErrorAction Stop
                $basicAuthScmEnabled = ($scmPolicy.properties.allow -eq $true)
            }
            catch { Write-Verbose "    Could not retrieve SCM basic auth policy for $appName" }

            try {
                $ftpPolicy = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Web/sites/$appName/basicPublishingCredentialsPolicies/ftp?api-version=2023-12-01" `
                    -AccessToken $AccessToken -Method GET -ErrorAction Stop
                $basicAuthFtpEnabled = ($ftpPolicy.properties.allow -eq $true)
            }
            catch { Write-Verbose "    Could not retrieve FTP basic auth policy for $appName" }

            # Auth settings (non-fatal)
            $authEnabled = $null
            try {
                $authSettings = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Web/sites/$appName/config/authsettingsV2?api-version=2023-12-01" `
                    -AccessToken $AccessToken -Method GET -ErrorAction Stop
                $authEnabled = ($authSettings.properties.platform.enabled -eq $true)
                $authDisabled = ($authEnabled -ne $true)
            }
            catch {
                Write-Verbose "    Could not retrieve auth settings for $appName"
            }

            # Managed Identity
            $hasMI           = ($app.identity -and $null -ne $app.identity.type)
            $miType          = if ($hasMI) { $app.identity.type } else { $null }
            $miPrincipalId   = if ($hasMI -and $app.identity.principalId) { $app.identity.principalId } else { $null }

            # VNet integration
            $vnetIntegration = ($null -ne $props.virtualNetworkSubnetId -and $props.virtualNetworkSubnetId -ne '')

            # Network access restrictions (IP rules)
            $ipRestrictions      = $null
            $noIpRestrictions    = $true
            if ($siteConfig) {
                $ipRestrictions   = $siteConfig.properties.ipSecurityRestrictions
                $noIpRestrictions = ($null -eq $ipRestrictions -or @($ipRestrictions).Count -eq 0 -or
                    ($ipRestrictions | Where-Object { $_.ipAddress -eq 'Any' -and $_.action -eq 'Allow' }).Count -gt 0)
            }

            # Staging slots
            $slots          = @()
            $slotCount      = 0
            $slotObjects    = [System.Collections.Generic.List[PSCustomObject]]::new()

            if ($IncludeSlots) {
                try {
                    $slotsResp = Invoke-AzRARequest `
                        -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Web/sites/$appName/slots?api-version=2023-12-01" `
                        -AccessToken $AccessToken -Method GET -EnablePagination -ErrorAction Stop
                    if ($slotsResp) {
                        $slots     = @($slotsResp)
                        $slotCount = $slots.Count
                    }
                }
                catch {
                    Write-Verbose "    Could not retrieve slots for $appName"
                }
            }
            else {
                # Just get count without details
                try {
                    $slotsResp = Invoke-AzRARequest `
                        -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Web/sites/$appName/slots?api-version=2023-12-01" `
                        -AccessToken $AccessToken -Method GET -EnablePagination -ErrorAction Stop
                    if ($slotsResp) { $slotCount = @($slotsResp).Count }
                }
                catch {}
            }

            # -- App settings extraction (-ScanSecrets) ------------------------

            $secrets        = [System.Collections.Generic.List[PSCustomObject]]::new()
            $hasSecrets     = $false
            $secretsRaw     = $null

            if ($ScanSecrets) {
                Write-Host "      [~] Intentando extraer app settings..." -ForegroundColor Gray
                $listUri     = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Web/sites/$appName/config/appsettings/list?api-version=2023-12-01"
                $secretsResp = Invoke-ListSecrets -Uri $listUri

                if ($secretsResp -and $secretsResp.properties) {
                    $secretsRaw = $secretsResp
                    $props2     = $secretsResp.properties
                    # Properties is a flat object - enumerate all key/value pairs
                    $props2.PSObject.Properties | ForEach-Object {
                        $setting = [PSCustomObject]@{
                            SubscriptionName = $subName
                            SubscriptionId   = $subId
                            ResourceGroup    = $rgName
                            AppName          = $appName
                            Kind             = $kind
                            SlotName         = 'production'
                            Name             = $_.Name
                            Value            = $_.Value
                        }
                        $secrets.Add($setting)
                        $allSecrets.Add($setting)
                    }
                    $hasSecrets = ($secrets.Count -gt 0)
                    Write-Host "      [+] App settings extraidas: $($secrets.Count)" -ForegroundColor $(if ($hasSecrets) { 'Red' } else { 'White' })
                }

                # Slots secrets
                if ($IncludeSlots -and $slots.Count -gt 0) {
                    foreach ($slot in $slots) {
                        $slotName    = $slot.name -replace "^$appName/", ''
                        $slotListUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Web/sites/$appName/slots/$slotName/config/appsettings/list?api-version=2023-12-01"
                        $slotSecResp = Invoke-ListSecrets -Uri $slotListUri
                        if ($slotSecResp -and $slotSecResp.properties) {
                            $slotSecResp.properties.PSObject.Properties | ForEach-Object {
                                $setting = [PSCustomObject]@{
                                    SubscriptionName = $subName
                                    SubscriptionId   = $subId
                                    ResourceGroup    = $rgName
                                    AppName          = $appName
                                    Kind             = $kind
                                    SlotName         = $slotName
                                    Name             = $_.Name
                                    Value            = $_.Value
                                }
                                $secrets.Add($setting)
                                $allSecrets.Add($setting)
                            }
                            $slotObjects.Add([PSCustomObject]@{
                                SlotName    = $slotName
                                SecretCount = $slotSecResp.properties.PSObject.Properties.Count
                            })
                        }
                    }
                }
            }

            # -- Summary flags -------------------------------------------------

            $hasCritical = (
                $httpsOnlyDisabled -or
                ($authDisabled -eq $true -and $noIpRestrictions) -or
                ($publicScmAccess -and -not $vnetIntegration) -or
                $hasSecrets
            )
            $hasHigh = (
                $minTlsWeak -or
                $ftpEnabled -or
                ($basicAuthScmEnabled -eq $true) -or
                ($basicAuthFtpEnabled -eq $true) -or
                $remoteDebugging -or
                $runtimeEol -or
                $alwaysOnDisabled -or
                ($hasMI -and -not $vnetIntegration)
            )

            if ($hasCritical) {
                Write-Host "    [!] CRITICO: $appName" -ForegroundColor Red
                if ($httpsOnlyDisabled)                              { Write-Host "        - HttpsOnlyDisabled: permite trafico HTTP sin cifrar" -ForegroundColor Red }
                if ($authDisabled -eq $true -and $noIpRestrictions) { Write-Host "        - AuthDisabled + sin restricciones IP: app publica sin autenticacion" -ForegroundColor Red }
                if ($publicScmAccess -and -not $vnetIntegration)    { Write-Host "        - PublicSCMAccess: consola Kudu accesible publicamente (posible RCE)" -ForegroundColor Red }
                if ($hasSecrets)                                     { Write-Host "        - AppSettings extraidas: $($secrets.Count) valores en texto claro" -ForegroundColor Red }
            }
            elseif ($hasHigh) {
                Write-Host "    [!] ALTO: $appName" -ForegroundColor Yellow
                if ($minTlsWeak)                    { Write-Host "        - MinTlsWeak: version TLS minima debil ($($siteConfig.properties.minTlsVersion))" -ForegroundColor Yellow }
                if ($ftpEnabled)                    { Write-Host "        - FtpEnabled: FTP no deshabilitado (estado: $($siteConfig.properties.ftpsState))" -ForegroundColor Yellow }
                if ($basicAuthScmEnabled -eq $true) { Write-Host "        - BasicAuthSCMEnabled: autenticacion basica habilitada en endpoint SCM/Kudu" -ForegroundColor Yellow }
                if ($basicAuthFtpEnabled -eq $true) { Write-Host "        - BasicAuthFTPEnabled: autenticacion basica habilitada en endpoint FTP" -ForegroundColor Yellow }
                if ($runtimeEol)                    { Write-Host "        - RuntimeEOL: version de runtime fuera de soporte ($runtimeVersion)" -ForegroundColor Yellow }
                if ($remoteDebugging)               { Write-Host "        - RemoteDebuggingEnabled: depuracion remota activa" -ForegroundColor Yellow }
                if ($alwaysOnDisabled)              { Write-Host "        - AlwaysOnDisabled: Function App con cold starts (puede evadir monitoreo)" -ForegroundColor Yellow }
                if ($hasMI -and -not $vnetIntegration) { Write-Host "        - ManagedIdentity sin VNet integration: MI con acceso directo a internet ($miType)" -ForegroundColor Yellow }
            }
            else {
                Write-Host "    [OK] $appName" -ForegroundColor Green
            }

            # -- Raw dump ------------------------------------------------------

            $rawFilePath = $null
            if ($dumpRoot -and $rgName) {
                $safeSubName = $subName  -replace '[^a-zA-Z0-9_\-]', '_'
                $safeAppName = $appName  -replace '[^a-zA-Z0-9_\-]', '_'
                $appDumpDir  = Join-Path (Join-Path $dumpRoot $safeSubName) $safeAppName

                if (-not (Test-Path $appDumpDir)) {
                    try {
                        New-Item -ItemType Directory -Force -Path $appDumpDir -ErrorAction Stop | Out-Null
                    }
                    catch { Write-Warning "  Could not create dump dir '$appDumpDir': $_" }
                }

                if (Test-Path $appDumpDir) {
                    try {
                        $app | ConvertTo-Json -Depth 20 |
                            Set-Content -Path (Join-Path $appDumpDir 'app.json') -Encoding UTF8 -ErrorAction Stop
                    }
                    catch { Write-Warning "  Could not write app.json for '$appName': $_" }

                    if ($secretsRaw) {
                        try {
                            $secretsRaw | ConvertTo-Json -Depth 10 |
                                Set-Content -Path (Join-Path $appDumpDir 'appsettings.json') -Encoding UTF8 -ErrorAction Stop
                        }
                        catch { Write-Warning "  Could not write appsettings.json for '$appName': $_" }
                    }

                    if ($slots.Count -gt 0) {
                        try {
                            $slots | ConvertTo-Json -Depth 10 |
                                Set-Content -Path (Join-Path $appDumpDir 'slots.json') -Encoding UTF8 -ErrorAction Stop
                        }
                        catch { Write-Warning "  Could not write slots.json for '$appName': $_" }
                    }

                    $rawFilePath = $appDumpDir
                }
            }

            # -- Build pipeline object -----------------------------------------

            $obj = [PSCustomObject]@{
                # Identity
                SubscriptionId   = $subId
                SubscriptionName = $subName
                ResourceGroup    = $rgName
                AppName          = $appName
                Kind             = $kind
                IsFunctionApp    = $isFuncApp
                Location         = $app.location
                DefaultHostName  = $props.defaultHostName
                State            = $props.state
                RuntimeStack     = if ($siteConfig) { "$($siteConfig.properties.linuxFxVersion)$($siteConfig.properties.windowsFxVersion)" } else { $null }

                # Critical checks
                HttpsOnlyDisabled    = $httpsOnlyDisabled
                AuthDisabled         = $authDisabled
                PublicScmAccess      = $publicScmAccess
                NoIpRestrictions     = $noIpRestrictions

                # High checks
                MinTlsWeak           = $minTlsWeak
                FtpEnabled           = $ftpEnabled
                RemoteDebuggingEnabled = $remoteDebugging
                AlwaysOnDisabled     = $alwaysOnDisabled
                ClientCertDisabled   = $clientCertDisabled
                BasicAuthScmEnabled  = $basicAuthScmEnabled
                BasicAuthFtpEnabled  = $basicAuthFtpEnabled
                RuntimeEol           = $runtimeEol
                RuntimeVersion       = $runtimeVersion

                # Informational
                HasManagedIdentity   = $hasMI
                ManagedIdentityType  = $miType
                ManagedIdentityPrincipalId = $miPrincipalId
                VNetIntegrated       = $vnetIntegration
                SlotCount            = $slotCount

                # Secrets (if -ScanSecrets)
                HasSecrets           = $hasSecrets
                SecretCount          = $secrets.Count
                Secrets              = $secrets.ToArray()

                # Summary flags
                HasCriticalFindings  = $hasCritical
                HasHighFindings      = $hasHigh

                RawFilePath          = $rawFilePath
            }

            $allApps.Add($obj)
        }
    }

    # -- Export CSVs -----------------------------------------------------------

    if ($OutputPath -and $allApps.Count -gt 0) {
        try {
            $allApps.ToArray() | Select-Object SubscriptionName, ResourceGroup, AppName, Kind,
                IsFunctionApp, Location, DefaultHostName, State, RuntimeStack,
                HttpsOnlyDisabled, AuthDisabled, PublicScmAccess, NoIpRestrictions,
                MinTlsWeak, FtpEnabled, BasicAuthScmEnabled, BasicAuthFtpEnabled, RuntimeEol, RuntimeVersion,
                RemoteDebuggingEnabled, AlwaysOnDisabled, ClientCertDisabled,
                HasManagedIdentity, ManagedIdentityType, ManagedIdentityPrincipalId,
                VNetIntegrated, SlotCount,
                HasSecrets, SecretCount,
                HasCriticalFindings, HasHighFindings, RawFilePath |
                Export-Csv -Path (Join-Path $OutputPath "AzRA-FunctionApps_$timestamp.csv") `
                           -NoTypeInformation -Encoding UTF8
        }
        catch { Write-Warning "Could not export FunctionApps CSV: $_" }

        if ($ScanSecrets -and $allSecrets.Count -gt 0) {
            try {
                $allSecrets.ToArray() | Export-Csv `
                    -Path (Join-Path $OutputPath "AzRA-FunctionApps-Secrets_$timestamp.csv") `
                    -NoTypeInformation -Encoding UTF8
            }
            catch { Write-Warning "Could not export secrets CSV: $_" }
        }
    }

    # -- Final summary ---------------------------------------------------------

    $criticalCount = ($allApps | Where-Object { $_.HasCriticalFindings }).Count
    $highCount     = ($allApps | Where-Object { $_.HasHighFindings -and -not $_.HasCriticalFindings }).Count
    $secretsTotal  = ($allApps | Measure-Object -Property SecretCount -Sum).Sum
    $totalCount    = $allApps.Count

    Write-Host ""
    Write-Host "[*] Auditoria completada: $totalCount apps analizadas" -ForegroundColor Cyan

    if ($criticalCount -gt 0) {
        Write-Host "  [!] Apps con hallazgos CRITICOS: $criticalCount" -ForegroundColor Red
        $allApps | Where-Object { $_.HasCriticalFindings } | ForEach-Object {
            $flags = @()
            if ($_.HttpsOnlyDisabled)   { $flags += 'HttpsOnly' }
            if ($_.AuthDisabled)        { $flags += 'AuthDisabled' }
            if ($_.PublicScmAccess)     { $flags += 'SCM' }
            if ($_.HasSecrets)          { $flags += "$($_.SecretCount) secrets" }
            Write-Host "    - $($_.AppName): $($flags -join ', ')" -ForegroundColor Red
        }
    }

    if ($highCount -gt 0) {
        Write-Host "  [!] Apps con hallazgos ALTOS: $highCount" -ForegroundColor Yellow
    }

    if ($ScanSecrets) {
        $appsWithSecrets = ($allApps | Where-Object { $_.HasSecrets }).Count
        Write-Host "  [+] App settings extraidas de $appsWithSecrets apps ($secretsTotal valores en total)" -ForegroundColor White
    }

    if ($OutputPath) {
        Write-Host "  [+] Resultados exportados en: $OutputPath" -ForegroundColor White
    }
    Write-Host ""

    return $allApps.ToArray()
}
