# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-ContainerRegistries {
    <#
    .SYNOPSIS
    Enumerates Azure Container Registries and audits them for security misconfigurations.
    Optionally enumerates repositories/tags/image sizes via ACR data plane API, and supports
    interactive selection of images to pull.

    .DESCRIPTION
    Iterates across all accessible subscriptions (or a specific one), lists all ACRs, and
    evaluates each against security checks:

      Critical:     AnonymousPullEnabled, AdminUserEnabled, PublicNetworkAccessEnabled
      High:         NoFirewallRules, RetentionPolicyDisabled, ContentTrustDisabled,
                    DiagnosticLogsDisabled, BasicSku
      Informational: NoPrivateEndpoints, ZoneRedundancyDisabled

    With -ScanRepositories, exchanges the ARM token for an ACR data plane token and enumerates
    repositories, tags, and compressed image sizes (config + layers from manifest v2).

    With -InteractivePull, displays a table of repos/tags with sizes and prompts the user
    to select which images to pull. Always generates a pull commands .txt file.

    Required ARM permissions:
      Microsoft.ContainerRegistry/registries/read
      Microsoft.ContainerRegistry/registries/listCredentials/action  (optional, only if admin user enabled)
      microsoft.insights/diagnosticSettings/read                     (optional, for log check)

    Required for -ScanRepositories:
      ARM token is exchanged via ACR oauth2/exchange endpoint. No extra ARM permissions needed
      beyond registry read access.

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription by ID. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where all output is saved. Raw JSON dumps are saved under:
      <OutputPath>\ContainerRegistriesRawDump\<SubscriptionName>\<RegistryName>\registry.json
      <OutputPath>\ContainerRegistriesRawDump\<SubscriptionName>\<RegistryName>\diagnostics.json
      <OutputPath>\ContainerRegistriesRawDump\<SubscriptionName>\<RegistryName>\repositories.json
    CSV reports saved as:
      <OutputPath>\AzRA-ContainerRegistries_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-ContainerRegistries-Repos_<yyyyMMdd-HHmm>.csv   (if -ScanRepositories)
      <OutputPath>\AzRA-ACR-PullCommands_<yyyyMMdd-HHmm>.txt            (if -ScanRepositories)

    .PARAMETER ScanRepositories
    If specified, exchanges the ARM token for an ACR data plane token per registry and
    enumerates repositories, tags, and compressed image sizes via the ACR v2 API.

    .PARAMETER InteractivePull
    If specified (implies -ScanRepositories), displays a table of all accessible repos/tags
    with sizes and prompts for interactive selection of images to docker pull.
    Requires Docker to be installed and running.

    .PARAMETER MaxRetries
    Maximum retry attempts on throttling (HTTP 429) or transient errors (5xx). Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-ContainerRegistries -AccessToken $token
    Enumerates all ACRs with ARM-level security checks.

    .EXAMPLE
    Get-AzRA-ContainerRegistries -AccessToken $token -ScanRepositories -OutputPath 'C:\Audit'
    Full audit: ARM checks + repository/tag/size enumeration + CSVs + raw dumps.

    .EXAMPLE
    Get-AzRA-ContainerRegistries -AccessToken $token -ScanRepositories -InteractivePull
    Enumerates repos and sizes, then prompts to select images for docker pull.

    .EXAMPLE
    $result = Get-AzRA-ContainerRegistries -AccessToken $token
    $result | Where-Object { $_.AdminUserEnabled -or $_.AnonymousPullEnabled }
    Find registries with highest risk access configurations.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    One object per registry containing identity fields, boolean security checks, and
    optionally repository enumeration results.
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
        [switch]$ScanRepositories,

        [Parameter(Mandatory = $false)]
        [switch]$InteractivePull,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySec = 5
    )

    # -- Implicit flag propagation --------------------------------------------
    if ($InteractivePull) { $ScanRepositories = $true }

    # -- Private helpers -------------------------------------------------------

    function Get-ArmHeaders {
        return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    }

    function Get-RgFromId {
        param([string]$ResourceId)
        if ($ResourceId -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
        return $null
    }

    function Get-AcrRefreshToken {
        param([string]$LoginServer, [string]$ArmToken)
        $uri  = "https://$LoginServer/oauth2/exchange"
        $body = "grant_type=access_token&service=$LoginServer&access_token=$ArmToken"
        try {
            $resp = Invoke-RestMethod -Uri $uri -Method POST `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body $body -ErrorAction Stop
            return $resp.refresh_token
        }
        catch {
            Write-Warning "  [ACR] Token exchange failed for $LoginServer`: $_"
            return $null
        }
    }

    function Get-AcrAccessToken {
        param([string]$LoginServer, [string]$RefreshToken, [string]$Scope)
        $uri  = "https://$LoginServer/oauth2/token"
        $body = "grant_type=refresh_token&service=$LoginServer&scope=$Scope&refresh_token=$RefreshToken"
        try {
            $resp = Invoke-RestMethod -Uri $uri -Method POST `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body $body -ErrorAction Stop
            return $resp.access_token
        }
        catch {
            Write-Warning "  [ACR] Access token request failed ($Scope) for $LoginServer`: $_"
            return $null
        }
    }

    function Get-AcrCatalog {
        param([string]$LoginServer, [string]$CatalogToken)
        $repos    = [System.Collections.Generic.List[string]]::new()
        $uri      = "https://$LoginServer/v2/_catalog?n=100"
        $headers  = @{ 'Authorization' = "Bearer $CatalogToken" }
        try {
            do {
                $resp = Invoke-WebRequest -Uri $uri -Headers $headers -Method GET -UseBasicParsing -ErrorAction Stop
                $body = $resp.Content | ConvertFrom-Json
                if ($body.repositories) {
                    foreach ($r in $body.repositories) { $repos.Add($r) }
                }
                # Pagination via Link header
                $linkHeader = $resp.Headers['Link']
                if ($linkHeader -and $linkHeader -match '<([^>]+)>;\s*rel="next"') {
                    $uri = "https://$LoginServer$($Matches[1])"
                }
                else {
                    $uri = $null
                }
            } while ($uri)
        }
        catch {
            Write-Warning "  [ACR] Catalog enumeration failed for $LoginServer`: $_"
        }
        return $repos.ToArray()
    }

    function Get-AcrTags {
        param([string]$LoginServer, [string]$Repo, [string]$RepoToken)
        $uri     = "https://$LoginServer/v2/$Repo/tags/list"
        $headers = @{ 'Authorization' = "Bearer $RepoToken" }
        try {
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction Stop
            return @($resp.tags)
        }
        catch {
            Write-Warning "  [ACR] Tags enumeration failed for $LoginServer/$Repo`: $_"
            return @()
        }
    }

    function Get-ManifestSize {
        param([string]$LoginServer, [string]$Repo, [string]$Tag, [string]$RepoToken)
        $uri     = "https://$LoginServer/v2/$Repo/manifests/$Tag"
        $headers = @{
            'Authorization' = "Bearer $RepoToken"
            'Accept'        = 'application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json'
        }
        try {
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction Stop
            $size = 0L
            if ($resp.config -and $resp.config.size) { $size += [long]$resp.config.size }
            if ($resp.layers) { foreach ($l in $resp.layers) { if ($l.size) { $size += [long]$l.size } } }
            return $size
        }
        catch { return 0L }
    }

    # -- Initialization --------------------------------------------------------

    $allRegistries   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allReposForCsv  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $pullCommands    = [System.Collections.Generic.List[string]]::new()
    $timestamp       = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot        = $null

    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
            $dumpRoot = Join-Path $OutputPath 'ContainerRegistriesRawDump'
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
    Write-Host "[*] Container Registries - iniciando auditoria..." -ForegroundColor Cyan

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
        Write-Host "    [~] Enumerando Container Registries..." -ForegroundColor Gray

        $registries = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $registries) {
            Write-Host "    [~] Sin Container Registries en esta subscripcion" -ForegroundColor Gray
            continue
        }

        Write-Host "    [+] Registries encontrados: $(@($registries).Count)" -ForegroundColor White

        foreach ($registry in $registries) {
            $regName     = $registry.name
            $rgName      = Get-RgFromId -ResourceId $registry.id
            $props       = $registry.properties
            $loginServer = $props.loginServer
            if (-not $loginServer) { $loginServer = "$regName.azurecr.io" }

            Write-Host "    [~] Analizando: $regName ($loginServer)" -ForegroundColor Gray

            # -- ARM security checks -------------------------------------------

            # Critical
            $anonymousPull     = ($props.anonymousPullEnabled -eq $true)
            $adminUserEnabled  = ($props.adminUserEnabled -eq $true)
            $networkRules      = $props.networkRuleSet
            $defaultAction     = if ($networkRules -and $networkRules.defaultAction) { $networkRules.defaultAction } else { 'Allow' }
            $ipRules           = if ($networkRules -and $networkRules.ipRules) { @($networkRules.ipRules) } else { @() }
            $publicNetEnabled  = ($defaultAction -eq 'Allow' -and $ipRules.Count -eq 0)

            # High
            $noFirewallRules   = ($defaultAction -eq 'Allow' -and $ipRules.Count -eq 0)
            $policies          = $props.policies
            $retentionDisabled = ($null -eq $policies -or $null -eq $policies.retentionPolicy -or $policies.retentionPolicy.status -ne 'enabled')
            $contentTrustDis   = ($null -eq $policies -or $null -eq $policies.trustPolicy -or $policies.trustPolicy.status -ne 'enabled')
            $basicSku          = ($registry.sku.name -eq 'Basic')

            # Informational
            $privateEndpoints  = @($props.privateEndpointConnections)
            $noPrivateEp       = ($privateEndpoints.Count -eq 0)
            $zoneRedundancyDis = ($props.zoneRedundancy -ne 'Enabled')

            # Diagnostic settings (non-fatal)
            $diagLogsDisabled = $null
            try {
                $diagSettings = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/$($registry.id)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview" `
                    -AccessToken $AccessToken -Method GET -ErrorAction Stop
                $diagLogsDisabled = ($null -eq $diagSettings -or @($diagSettings).Count -eq 0)
            }
            catch {
                Write-Verbose "    Sin acceso a diagnostic settings para $regName"
            }

            # Admin credentials (only if admin user enabled)
            $adminUsername = $null
            if ($adminUserEnabled -and $rgName) {
                try {
                    $creds = Invoke-AzRARequest `
                        -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.ContainerRegistry/registries/$regName/listCredentials?api-version=2023-07-01" `
                        -AccessToken $AccessToken -Method POST -ErrorAction Stop
                    if ($creds -and $creds.username) {
                        $adminUsername = $creds.username
                        Write-Host "    [!] Admin credentials obtenidas: $adminUsername" -ForegroundColor Red
                    }
                }
                catch {
                    Write-Warning "    [403] Sin permiso para listCredentials en $regName (requiere listCredentials/action)"
                }
            }

            # -- Data plane: repository enumeration ----------------------------

            $dataPlaneAccessible = $null
            $repoObjects         = [System.Collections.Generic.List[PSCustomObject]]::new()
            $repositoryCount     = $null
            $totalImageSizeBytes = $null

            if ($ScanRepositories) {
                Write-Host "      [~] Intentando acceso al data plane..." -ForegroundColor Gray
                $acrRefreshToken = Get-AcrRefreshToken -LoginServer $loginServer -ArmToken $AccessToken

                if ($acrRefreshToken) {
                    $dataPlaneAccessible = $true
                    Write-Host "      [+] Token ACR obtenido para $loginServer" -ForegroundColor Green

                    # Get catalog token
                    $catalogToken = Get-AcrAccessToken -LoginServer $loginServer -RefreshToken $acrRefreshToken -Scope 'registry:catalog:*'

                    if ($catalogToken) {
                        $repoNames = Get-AcrCatalog -LoginServer $loginServer -CatalogToken $catalogToken
                        $repositoryCount  = $repoNames.Count
                        $totalImageSizeBytes = 0L

                        Write-Host "      [+] Repositorios encontrados: $repositoryCount" -ForegroundColor White

                        foreach ($repoName in $repoNames) {
                            # Get per-repo pull token
                            $repoScope = "repository:${repoName}:pull"
                            $repoToken = Get-AcrAccessToken -LoginServer $loginServer -RefreshToken $acrRefreshToken -Scope $repoScope
                            if (-not $repoToken) { continue }

                            $tags        = Get-AcrTags -LoginServer $loginServer -Repo $repoName -RepoToken $repoToken
                            $repoSizeB   = 0L
                            $tagObjects  = [System.Collections.Generic.List[PSCustomObject]]::new()

                            foreach ($tag in $tags) {
                                $imgSize = Get-ManifestSize -LoginServer $loginServer -Repo $repoName -Tag $tag -RepoToken $repoToken
                                $repoSizeB += $imgSize
                                $imageRef   = "$loginServer/${repoName}:${tag}"
                                $tagObjects.Add([PSCustomObject]@{
                                    Image         = $imageRef
                                    Registry      = $loginServer
                                    Repository    = $repoName
                                    Tag           = $tag
                                    SizeBytes     = $imgSize
                                    SizeMB        = [Math]::Round($imgSize / 1MB, 1)
                                })
                                $pullCommands.Add("docker pull $imageRef")

                                # CSV row
                                $allReposForCsv.Add([PSCustomObject]@{
                                    SubscriptionName = $subName
                                    RegistryName     = $regName
                                    LoginServer      = $loginServer
                                    Repository       = $repoName
                                    Tag              = $tag
                                    ImageRef         = $imageRef
                                    SizeBytes        = $imgSize
                                    SizeMB           = [Math]::Round($imgSize / 1MB, 1)
                                })
                            }

                            $totalImageSizeBytes += $repoSizeB
                            $repoObjects.Add([PSCustomObject]@{
                                RepositoryName   = $repoName
                                Tags             = ($tags -join ', ')
                                TagCount         = $tags.Count
                                TotalSizeBytes   = $repoSizeB
                                TagObjects       = $tagObjects.ToArray()
                            })
                        }

                        $totalGB = [Math]::Round($totalImageSizeBytes / 1GB, 2)
                        Write-Host "      [+] Tamano total (comprimido): $totalGB GB" -ForegroundColor White
                    }
                    else {
                        Write-Warning "      [ACR] No se pudo obtener catalog token para $loginServer"
                        $dataPlaneAccessible = $false
                    }
                }
                else {
                    $dataPlaneAccessible = $false
                    Write-Host "      [-] Sin acceso al data plane de $loginServer" -ForegroundColor DarkGray
                }
            }

            # -- Summary flags -------------------------------------------------

            $hasCritical = ($anonymousPull -or $adminUserEnabled -or $publicNetEnabled)
            $hasHigh     = ($noFirewallRules -or $retentionDisabled -or $contentTrustDis -or
                           ($diagLogsDisabled -eq $true) -or $basicSku)

            if ($hasCritical) {
                Write-Host "    [!] CRITICO: $regName" -ForegroundColor Red
                if ($anonymousPull)    { Write-Host "        - AnonymousPullEnabled: cualquier usuario puede hacer pull sin autenticacion" -ForegroundColor Red }
                if ($adminUserEnabled) { Write-Host "        - AdminUserEnabled: credenciales de admin estaticas habilitadas$(if ($adminUsername) { " ($adminUsername)" })" -ForegroundColor Red }
                if ($publicNetEnabled) { Write-Host "        - PublicNetworkAccessEnabled: sin restricciones de red (defaultAction=Allow, sin reglas IP)" -ForegroundColor Red }
            }
            elseif ($hasHigh) {
                Write-Host "    [!] ALTO: $regName" -ForegroundColor Yellow
                if ($noFirewallRules)              { Write-Host "        - NoFirewallRules: sin reglas de firewall IP configuradas" -ForegroundColor Yellow }
                if ($retentionDisabled)            { Write-Host "        - RetentionPolicyDisabled: sin politica de retencion de imagenes" -ForegroundColor Yellow }
                if ($contentTrustDis)              { Write-Host "        - ContentTrustDisabled: firma de imagenes no habilitada" -ForegroundColor Yellow }
                if ($diagLogsDisabled -eq $true)   { Write-Host "        - DiagnosticLogsDisabled: sin Diagnostic Settings configurados" -ForegroundColor Yellow }
                if ($basicSku)                     { Write-Host "        - BasicSku: SKU Basic sin soporte para content trust ni private endpoints" -ForegroundColor Yellow }
            }
            else {
                Write-Host "    [OK] $regName" -ForegroundColor Green
            }

            # -- Raw dump ------------------------------------------------------

            $rawFilePath = $null
            if ($dumpRoot -and $rgName) {
                $safeSubName = $subName   -replace '[^a-zA-Z0-9_\-]', '_'
                $safeRegName = $regName   -replace '[^a-zA-Z0-9_\-]', '_'
                $regDumpDir  = Join-Path (Join-Path $dumpRoot $safeSubName) $safeRegName

                if (-not (Test-Path $regDumpDir)) {
                    try {
                        New-Item -ItemType Directory -Force -Path $regDumpDir -ErrorAction Stop | Out-Null
                    }
                    catch { Write-Warning "  Could not create dump dir '$regDumpDir': $_" }
                }

                if (Test-Path $regDumpDir) {
                    try {
                        $registry | ConvertTo-Json -Depth 20 |
                            Set-Content -Path (Join-Path $regDumpDir 'registry.json') -Encoding UTF8 -ErrorAction Stop
                    }
                    catch { Write-Warning "  Could not write registry.json for '$regName': $_" }

                    if ($null -ne $diagLogsDisabled) {
                        try {
                            @{ diagLogsDisabled = $diagLogsDisabled } | ConvertTo-Json |
                                Set-Content -Path (Join-Path $regDumpDir 'diagnostics.json') -Encoding UTF8 -ErrorAction Stop
                        }
                        catch { Write-Warning "  Could not write diagnostics.json for '$regName': $_" }
                    }

                    if ($repoObjects.Count -gt 0) {
                        try {
                            $repoObjects.ToArray() | ConvertTo-Json -Depth 10 |
                                Set-Content -Path (Join-Path $regDumpDir 'repositories.json') -Encoding UTF8 -ErrorAction Stop
                        }
                        catch { Write-Warning "  Could not write repositories.json for '$regName': $_" }
                    }

                    $rawFilePath = $regDumpDir
                }
            }

            # -- Build pipeline object -----------------------------------------

            $obj = [PSCustomObject]@{
                # Identity
                SubscriptionId      = $subId
                SubscriptionName    = $subName
                ResourceGroup       = $rgName
                RegistryName        = $regName
                LoginServer         = $loginServer
                Location            = $registry.location
                Sku                 = $registry.sku.name
                CreatedDateTime     = $props.creationDate

                # Critical
                AnonymousPullEnabled       = $anonymousPull
                AdminUserEnabled           = $adminUserEnabled
                PublicNetworkAccessEnabled = $publicNetEnabled

                # High
                NoFirewallRules        = $noFirewallRules
                RetentionPolicyDisabled = $retentionDisabled
                ContentTrustDisabled   = $contentTrustDis
                DiagnosticLogsDisabled = $diagLogsDisabled
                BasicSku               = $basicSku

                # Informational
                NoPrivateEndpoints      = $noPrivateEp
                ZoneRedundancyDisabled  = $zoneRedundancyDis
                AdminUsername           = $adminUsername
                DataPlaneAccessible     = $dataPlaneAccessible
                RepositoryCount         = $repositoryCount
                TotalImageSizeGB        = if ($null -ne $totalImageSizeBytes) { [Math]::Round($totalImageSizeBytes / 1GB, 2) } else { $null }

                # Repository detail (if -ScanRepositories)
                Repositories = $repoObjects.ToArray()

                # Summary flags
                HasCriticalFindings = $hasCritical
                HasHighFindings     = $hasHigh

                RawFilePath = $rawFilePath
            }

            $allRegistries.Add($obj)
        }
    }

    # -- Interactive Pull ------------------------------------------------------

    if ($InteractivePull -and $allReposForCsv.Count -gt 0) {
        Write-Host ""
        Write-Host "[*] Seleccion interactiva de imagenes para docker pull" -ForegroundColor Cyan

        # Check docker available
        $dockerAvailable = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
        if (-not $dockerAvailable) {
            Write-Warning "  Docker no encontrado en el PATH. Genera el archivo de comandos pero no ejecutara pulls automaticos."
        }

        # Group by registry for display
        $byRegistry = $allReposForCsv | Group-Object -Property LoginServer

        $allTagObjects = [System.Collections.Generic.List[PSCustomObject]]::new()
        $idx = 1
        foreach ($group in $byRegistry) {
            $totalRegSize = ($group.Group | Measure-Object -Property SizeBytes -Sum).Sum
            $totalRegGB   = [Math]::Round($totalRegSize / 1GB, 2)
            Write-Host ""
            Write-Host "  Registry: $($group.Name)  ($($group.Group.Count) imagenes, $totalRegGB GB total)" -ForegroundColor White
            Write-Host ("  " + ("{0,-4} {1,-60} {2,-10}" -f "Idx", "Imagen", "Tamano")) -ForegroundColor Gray
            Write-Host ("  " + ("-" * 76)) -ForegroundColor DarkGray

            foreach ($img in $group.Group) {
                $sizeStr = if ($img.SizeMB -gt 1024) { "$([Math]::Round($img.SizeMB/1024,1)) GB" } else { "$($img.SizeMB) MB" }
                Write-Host ("  " + ("{0,-4} {1,-60} {2,-10}" -f "[$idx]", "$($img.Repository):$($img.Tag)", $sizeStr)) -ForegroundColor White
                $allTagObjects.Add([PSCustomObject]@{
                    Idx      = $idx
                    ImageRef = $img.ImageRef
                    SizeMB   = $img.SizeMB
                })
                $idx++
            }
        }

        Write-Host ""
        Write-Host "  Introduce los indices a descargar (ej: 1,3), 'all' para todos, 'none' para omitir:" -ForegroundColor Cyan
        $selection = Read-Host "  > "

        $selectedImages = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($selection -eq 'none' -or [string]::IsNullOrWhiteSpace($selection)) {
            Write-Host "  [~] Omitiendo pulls" -ForegroundColor Gray
        }
        elseif ($selection -eq 'all') {
            foreach ($t in $allTagObjects) { $selectedImages.Add($t) }
        }
        else {
            $indices = $selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
            foreach ($i in $indices) {
                $found = $allTagObjects | Where-Object { $_.Idx -eq [int]$i }
                if ($found) { $selectedImages.Add($found) }
            }
        }

        if ($selectedImages.Count -gt 0) {
            $totalSelGB = [Math]::Round(($selectedImages | Measure-Object -Property SizeMB -Sum).Sum / 1024, 2)

            # Extra confirmation if > 5 GB
            $proceed = $true
            if ($totalSelGB -gt 5) {
                Write-Host ""
                Write-Host "  [!] Tamano total seleccionado: $totalSelGB GB. Confirmar descarga? (s/N):" -ForegroundColor Yellow
                $confirm = Read-Host "  > "
                $proceed = ($confirm -match '^[sS]$')
            }

            if ($proceed -and $dockerAvailable) {
                foreach ($img in $selectedImages) {
                    Write-Host "  [~] Ejecutando: docker pull $($img.ImageRef)" -ForegroundColor Gray
                    try {
                        & docker pull $img.ImageRef
                    }
                    catch {
                        Write-Warning "  docker pull failed for $($img.ImageRef): $_"
                    }
                }
            }
            elseif (-not $proceed) {
                Write-Host "  [~] Pull cancelado por el usuario" -ForegroundColor Gray
            }
        }
    }

    # -- Export CSVs -----------------------------------------------------------

    if ($OutputPath) {
        # Main registry CSV
        try {
            $allRegistries.ToArray() | Select-Object SubscriptionName, RegistryName, LoginServer,
                Location, Sku, CreatedDateTime,
                AnonymousPullEnabled, AdminUserEnabled, PublicNetworkAccessEnabled,
                NoFirewallRules, RetentionPolicyDisabled, ContentTrustDisabled,
                DiagnosticLogsDisabled, BasicSku,
                NoPrivateEndpoints, ZoneRedundancyDisabled,
                AdminUsername, DataPlaneAccessible, RepositoryCount, TotalImageSizeGB,
                HasCriticalFindings, HasHighFindings |
                Export-Csv -Path (Join-Path $OutputPath "AzRA-ContainerRegistries_$timestamp.csv") `
                           -NoTypeInformation -Encoding UTF8
            Write-Verbose "  CSV: AzRA-ContainerRegistries_$timestamp.csv"
        }
        catch { Write-Warning "Could not export registries CSV: $_" }

        # Repos CSV
        if ($ScanRepositories -and $allReposForCsv.Count -gt 0) {
            try {
                $allReposForCsv.ToArray() | Export-Csv `
                    -Path (Join-Path $OutputPath "AzRA-ContainerRegistries-Repos_$timestamp.csv") `
                    -NoTypeInformation -Encoding UTF8
                Write-Verbose "  CSV: AzRA-ContainerRegistries-Repos_$timestamp.csv"
            }
            catch { Write-Warning "Could not export repos CSV: $_" }
        }

        # Pull commands .txt
        if ($ScanRepositories -and $pullCommands.Count -gt 0) {
            try {
                $pullCommands.ToArray() | Set-Content `
                    -Path (Join-Path $OutputPath "AzRA-ACR-PullCommands_$timestamp.txt") `
                    -Encoding UTF8
                Write-Verbose "  TXT: AzRA-ACR-PullCommands_$timestamp.txt"
            }
            catch { Write-Warning "Could not write pull commands file: $_" }
        }
    }

    # -- Final summary ---------------------------------------------------------

    $criticalCount = ($allRegistries | Where-Object { $_.HasCriticalFindings }).Count
    $highCount     = ($allRegistries | Where-Object { $_.HasHighFindings -and -not $_.HasCriticalFindings }).Count
    $totalCount    = $allRegistries.Count

    Write-Host ""
    Write-Host "[*] Auditoria completada: $totalCount registries analizados" -ForegroundColor Cyan

    if ($criticalCount -gt 0) {
        Write-Host "  [!] Registries con hallazgos CRITICOS: $criticalCount" -ForegroundColor Red
        $allRegistries | Where-Object { $_.HasCriticalFindings } | ForEach-Object {
            $flags = @()
            if ($_.AnonymousPullEnabled)       { $flags += 'AnonymousPull' }
            if ($_.AdminUserEnabled)           { $flags += 'AdminUser' }
            if ($_.PublicNetworkAccessEnabled) { $flags += 'PublicAccess' }
            Write-Host "    - $($_.LoginServer): $($flags -join ', ')" -ForegroundColor Red
        }
    }

    if ($highCount -gt 0) {
        Write-Host "  [!] Registries con hallazgos ALTOS: $highCount" -ForegroundColor Yellow
    }

    if ($ScanRepositories) {
        $accessible = ($allRegistries | Where-Object { $_.DataPlaneAccessible -eq $true }).Count
        Write-Host "  [+] Data plane accesible: $accessible / $totalCount registries" -ForegroundColor White
        if ($pullCommands.Count -gt 0) {
            Write-Host "  [+] Comandos docker pull generados: $($pullCommands.Count)" -ForegroundColor White
            if ($OutputPath) {
                Write-Host "  [+] Archivo de comandos: AzRA-ACR-PullCommands_$timestamp.txt" -ForegroundColor White
            }
        }
    }

    if ($OutputPath) {
        Write-Host "  [+] Resultados exportados en: $OutputPath" -ForegroundColor White
    }
    Write-Host ""

    return $allRegistries.ToArray()
}
