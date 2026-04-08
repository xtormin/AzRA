# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-AzureDevOps {
    <#
    .SYNOPSIS
    Enumerates Azure DevOps organizations, projects, service connections, variable groups,
    agent pools, and repositories. Audits for high-value credential exposure vectors.

    .DESCRIPTION
    Connects to the Azure DevOps REST API (dev.azure.com) and enumerates all accessible
    organizations and their projects. For each project, evaluates:

      - Service connections: classified by type and auth scheme
          AzureRM SPN connections, GitHub, AWS, Docker Registry, Generic HTTP
      - Variable groups: secret variable counts and Key Vault-linked groups
      - Agent pools: self-hosted pools as lateral movement vectors
      - Repositories: inventory with remote URLs

    Security findings:

      Critical:   AzureRM service connections with ServicePrincipal scheme
                  (SPN credentials may be extractable via API)
                  Variable groups linked to Azure Key Vault
                  (reveals which KV secrets are consumed by pipelines)
      High:       Any external service connection (GitHub, AWS, Docker, Generic HTTP)
                  Variable groups with secret variables
                  Self-hosted agent pools (SSRF / lateral movement path)
                  Publicly visible projects
      Info:       Repository inventory, pipeline counts

    With -ScanSecrets, retrieves full authorization parameters from service connections.
    For AzureRM SPN connections this includes serviceprincipalid, tenantid, and
    (if permitted) serviceprincipalkey.

    Required token: Azure AD Bearer token for Azure DevOps resource
      $devopsToken = (az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798 | ConvertFrom-Json).accessToken

    Or a Personal Access Token (PAT) with scopes:
      vso.project, vso.serviceendpoint, vso.variablegroups_read, vso.code, vso.agentpools
    Use -TokenIsPAT when passing a PAT.

    .PARAMETER AccessToken
    Azure DevOps access token. Can be an Azure AD Bearer token (resource
    499b84ac-1321-427f-aa17-267ca6975798) or a Personal Access Token (PAT).
    Use -TokenIsPAT when passing a PAT.

    .PARAMETER TokenIsPAT
    If specified, treats AccessToken as a PAT and encodes it as HTTP Basic auth.

    .PARAMETER Organization
    Target a specific Azure DevOps organization by name. If omitted, discovers
    all organizations accessible to the current identity via the VSTS profile API.

    .PARAMETER Project
    Limit enumeration to a specific project. Requires -Organization.

    .PARAMETER OutputPath
    Folder where output is saved. Raw dumps under:
      <OutputPath>\AzureDevOpsRawDump\<OrgName>\<ProjectName>\
    CSV reports:
      <OutputPath>\AzRA-AzDevOps-ServiceConnections_<timestamp>.csv
      <OutputPath>\AzRA-AzDevOps-VariableGroups_<timestamp>.csv
      <OutputPath>\AzRA-AzDevOps-AgentPools_<timestamp>.csv
      <OutputPath>\AzRA-AzDevOps-Repos_<timestamp>.csv

    .PARAMETER ScanSecrets
    Retrieves full authorization parameters from each service connection.
    For AzureRM ServicePrincipal connections this may include the SPN password.

    .EXAMPLE
    $devopsToken = (az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798 | ConvertFrom-Json).accessToken
    Get-AzRA-AzureDevOps -AccessToken $devopsToken

    .EXAMPLE
    Get-AzRA-AzureDevOps -AccessToken $devopsToken -ScanSecrets -OutputPath 'C:\Audit'

    .EXAMPLE
    # With PAT, targeting a specific org
    Get-AzRA-AzureDevOps -AccessToken 'mypatvalue' -TokenIsPAT -Organization 'myorg' -ScanSecrets

    .EXAMPLE
    $result = Get-AzRA-AzureDevOps -AccessToken $devopsToken -ScanSecrets
    $result.ServiceConnections | Where-Object { $_.HasCriticalFindings } | Format-Table Organization, Project, ConnectionName, AuthParams

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Object with keys: ServiceConnections, VariableGroups, AgentPools, Repositories
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]  [string]$AccessToken,
        [Parameter(Mandatory = $false)] [switch]$TokenIsPAT,
        [Parameter(Mandatory = $false)] [string]$Organization,
        [Parameter(Mandatory = $false)] [string]$Project,
        [Parameter(Mandatory = $false)] [string]$OutputPath,
        [Parameter(Mandatory = $false)] [switch]$ScanSecrets,
        [Parameter(Mandatory = $false)] [ValidateRange(1,10)] [int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)] [ValidateRange(1,60)] [int]$RetryDelaySec = 5
    )

    # -- Private helpers -------------------------------------------------------

    function Get-DevOpsHeaders {
        if ($TokenIsPAT) {
            $encoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$AccessToken"))
            return @{ 'Authorization' = "Basic $encoded"; 'Content-Type' = 'application/json' }
        }
        return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    }

    function Invoke-DevOpsGet {
        param([string]$Uri)
        $all = [System.Collections.Generic.List[object]]::new()
        $currentUri = $Uri
        do {
            try {
                $response = Invoke-WebRequest -Uri $currentUri -Headers (Get-DevOpsHeaders) `
                    -Method GET -ErrorAction Stop -UseBasicParsing
                $obj = $response.Content | ConvertFrom-Json

                if ($null -ne $obj.value) {
                    foreach ($item in $obj.value) { $all.Add($item) }
                }
                else {
                    # Single-object response (e.g., user profile)
                    return $obj
                }

                # Continuation token for pagination
                $ct = $response.Headers['X-MS-ContinuationToken']
                if ($ct) {
                    $sep = if ($currentUri -match '\?') { '&' } else { '?' }
                    $currentUri = "$Uri${sep}continuationToken=$ct"
                }
                else { $currentUri = $null }
            }
            catch {
                $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
                if ($code -in @(401, 403)) { Write-Warning "    [403] Sin permiso: $Uri"; return $null }
                elseif ($code -eq 404)     { Write-Verbose "    [404] No encontrado: $Uri"; return $null }
                else                       { Write-Verbose "    GET failed ($code): $Uri"; return $null }
            }
        } while ($currentUri)

        return $all.ToArray()
    }

    function Invoke-DevOpsPost {
        param([string]$Uri)
        try {
            return Invoke-RestMethod -Uri $Uri -Headers (Get-DevOpsHeaders) -Method POST `
                -Body '{}' -ContentType 'application/json' -ErrorAction Stop
        }
        catch {
            $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
            if ($code -in @(401, 403)) { Write-Warning "    [403] Sin permiso: $Uri" }
            else                       { Write-Verbose "    POST failed ($code): $Uri" }
            return $null
        }
    }

    # -- Init ------------------------------------------------------------------

    $allServiceConnections = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allVariableGroups     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allAgentPools         = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allRepos              = [System.Collections.Generic.List[PSCustomObject]]::new()

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot  = $null

    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null }
            $dumpRoot = Join-Path $OutputPath 'AzureDevOpsRawDump'
            if (-not (Test-Path $dumpRoot)) { New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null }
        }
        catch { throw "Cannot create output directory '$OutputPath': $_" }
    }

    Write-Host ""
    Write-Host "[*] Azure DevOps - iniciando reconocimiento..." -ForegroundColor Cyan

    # -- Discover organizations ------------------------------------------------

    $orgs = @()

    if ($Organization) {
        $orgs = @([PSCustomObject]@{ accountName = $Organization })
        Write-Host "  [~] Organizacion objetivo: $Organization" -ForegroundColor Gray
    }
    else {
        Write-Host "  [~] Descubriendo organizaciones accesibles..." -ForegroundColor Gray
        $profile = Invoke-DevOpsGet -Uri 'https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1'
        if (-not $profile) {
            Write-Warning "  [!] No se pudo obtener perfil de usuario. Usa -Organization para especificar la organizacion manualmente."
        }
        else {
            $userId = $profile.id
            Write-Host "  [+] Usuario: $($profile.displayName) ($userId)" -ForegroundColor White
            $orgList = Invoke-DevOpsGet -Uri "https://app.vssps.visualstudio.com/_apis/accounts?memberId=$userId&api-version=7.1"
            if ($orgList) {
                $orgs = @($orgList)
                Write-Host "  [+] Organizaciones encontradas: $($orgs.Count)" -ForegroundColor White
            }
            else {
                Write-Warning "  [!] Sin organizaciones accesibles. Verifica los permisos del token."
            }
        }
    }

    if ($orgs.Count -eq 0) {
        Write-Host "  [~] Sin organizaciones a analizar." -ForegroundColor Gray
        return [PSCustomObject]@{
            ServiceConnections = @()
            VariableGroups     = @()
            AgentPools         = @()
            Repositories       = @()
        }
    }

    # -- Enumerate organizations -----------------------------------------------

    foreach ($org in $orgs) {
        $orgName = $org.accountName

        Write-Host ""
        Write-Host "  [*] Organizacion: $orgName" -ForegroundColor Cyan

        # Agent pools (org-level resource)
        Write-Host "    [~] Enumerando agent pools..." -ForegroundColor Gray
        $pools = Invoke-DevOpsGet -Uri "https://dev.azure.com/$orgName/_apis/distributedtask/pools?api-version=7.1"

        if ($pools) {
            Write-Host "    [+] Agent pools: $(@($pools).Count)" -ForegroundColor White
            foreach ($pool in @($pools)) {
                $isSelfHosted = ($pool.isHosted -eq $false)
                $allAgentPools.Add([PSCustomObject]@{
                    Organization    = $orgName
                    PoolName        = $pool.name
                    PoolId          = $pool.id
                    IsHosted        = $pool.isHosted
                    IsSelfHosted    = $isSelfHosted
                    PoolType        = $pool.poolType
                    AgentCount      = $pool.size
                    HasHighFindings = $isSelfHosted
                })
                if ($isSelfHosted) {
                    Write-Host "    [!] ALTO: Pool self-hosted '$($pool.name)' - $($pool.size) agente(s) (lateral movement / pivoting)" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "    [~] Sin agent pools accesibles" -ForegroundColor Gray
        }

        # Enumerate projects
        Write-Host "    [~] Enumerando proyectos..." -ForegroundColor Gray
        $projects = Invoke-DevOpsGet -Uri "https://dev.azure.com/$orgName/_apis/projects?api-version=7.1&`$top=500"

        if (-not $projects) {
            Write-Host "    [~] Sin proyectos accesibles en $orgName" -ForegroundColor Gray
            continue
        }

        if ($Project) { $projects = @($projects | Where-Object { $_.name -eq $Project }) }

        Write-Host "    [+] Proyectos: $(@($projects).Count)" -ForegroundColor White

        foreach ($proj in @($projects)) {
            $projName       = $proj.name
            $projVisibility = $proj.visibility   # private / public

            Write-Host "      [~] Proyecto: $projName [$projVisibility]" -ForegroundColor Gray

            if ($projVisibility -eq 'public') {
                Write-Host "      [!] ALTO: Proyecto publico accesible sin autenticacion" -ForegroundColor Yellow
            }

            # Set up raw dump dir for this project
            $projDumpDir = $null
            if ($dumpRoot) {
                $projDumpDir = Join-Path (Join-Path $dumpRoot ($orgName -replace '[^a-zA-Z0-9_\-]','_')) ($projName -replace '[^a-zA-Z0-9_\-]','_')
                if (-not (Test-Path $projDumpDir)) {
                    try { New-Item -ItemType Directory -Force -Path $projDumpDir -ErrorAction Stop | Out-Null } catch {}
                }
            }

            # Service connections
            $serviceConns = Invoke-DevOpsGet -Uri "https://dev.azure.com/$orgName/$projName/_apis/serviceendpoint/endpoints?api-version=7.1&includeFailed=false"

            if ($serviceConns -and @($serviceConns).Count -gt 0) {
                Write-Host "        [+] Service connections: $(@($serviceConns).Count)" -ForegroundColor White

                if ($projDumpDir) {
                    try { $serviceConns | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $projDumpDir 'serviceConnections.json') -Encoding UTF8 } catch {}
                }

                foreach ($sc in @($serviceConns)) {
                    $scType   = $sc.type
                    $scScheme = $sc.authorization.scheme
                    $scName   = $sc.name

                    # Classify severity
                    $isCritical = ($scType -eq 'azurerm' -and $scScheme -eq 'ServicePrincipal')
                    $isHigh     = (-not $isCritical) -and ($scType -in @(
                        'azurerm','github','bitbucket','aws','dockerregistry',
                        'generic','externalgit','svn','ssh','token','UsernamePassword'
                    ))

                    # Extract auth params if ScanSecrets
                    $authParamsStr = $null
                    if ($ScanSecrets) {
                        $scDetail = Invoke-DevOpsGet -Uri "https://dev.azure.com/$orgName/$projName/_apis/serviceendpoint/endpoints/$($sc.id)?api-version=7.1"
                        if ($scDetail -and $scDetail.authorization -and $scDetail.authorization.parameters) {
                            $authParamsStr = ($scDetail.authorization.parameters.PSObject.Properties |
                                Where-Object { $_.Value } |
                                ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
                        }
                    }

                    $allServiceConnections.Add([PSCustomObject]@{
                        Organization        = $orgName
                        Project             = $projName
                        ProjectVisibility   = $projVisibility
                        ConnectionName      = $scName
                        ConnectionId        = $sc.id
                        Type                = $scType
                        Scheme              = $scScheme
                        IsShared            = $sc.isShared
                        IsReady             = $sc.isReady
                        CreatedBy           = $sc.createdBy.displayName
                        AuthParams          = $authParamsStr
                        HasCriticalFindings = $isCritical
                        HasHighFindings     = $isHigh
                    })

                    if ($isCritical) {
                        Write-Host "        [!] CRITICO: Service connection '$scName' [$scType/$scScheme]" -ForegroundColor Red
                        if ($authParamsStr) { Write-Host "            Params: $authParamsStr" -ForegroundColor Red }
                    }
                    elseif ($isHigh) {
                        Write-Host "        [!] ALTO: Service connection '$scName' [$scType]" -ForegroundColor Yellow
                    }
                }
            }

            # Variable groups
            $varGroups = Invoke-DevOpsGet -Uri "https://dev.azure.com/$orgName/$projName/_apis/distributedtask/variablegroups?api-version=7.1"

            if ($varGroups -and @($varGroups).Count -gt 0) {
                Write-Host "        [+] Variable groups: $(@($varGroups).Count)" -ForegroundColor White

                if ($projDumpDir) {
                    try { $varGroups | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $projDumpDir 'variableGroups.json') -Encoding UTF8 } catch {}
                }

                foreach ($vg in @($varGroups)) {
                    $vgName     = $vg.name
                    $vgType     = $vg.type   # 'Vsts' or 'AzureKeyVault'
                    $isKvLinked = ($vgType -eq 'AzureKeyVault')
                    $kvName     = if ($isKvLinked -and $vg.providerData) { $vg.providerData.vault } else { $null }

                    $secretCount = 0
                    $varPairs    = [System.Collections.Generic.List[string]]::new()

                    if ($vg.variables) {
                        $vg.variables.PSObject.Properties | ForEach-Object {
                            $vName = $_.Name
                            $vData = $_.Value
                            if ($vData.isSecret -eq $true) {
                                $secretCount++
                                $varPairs.Add("$vName=[SECRET]")
                            }
                            else {
                                $varPairs.Add("$vName=$($vData.value)")
                            }
                        }
                    }

                    $isCritical = $isKvLinked
                    $isHigh     = (-not $isKvLinked) -and ($secretCount -gt 0)

                    $allVariableGroups.Add([PSCustomObject]@{
                        Organization        = $orgName
                        Project             = $projName
                        GroupName           = $vgName
                        GroupId             = $vg.id
                        Type                = $vgType
                        IsKeyVaultLinked    = $isKvLinked
                        KeyVaultName        = $kvName
                        VariableCount       = $varPairs.Count
                        SecretCount         = $secretCount
                        Variables           = $varPairs -join '; '
                        HasCriticalFindings = $isCritical
                        HasHighFindings     = $isHigh
                    })

                    if ($isCritical) {
                        Write-Host "        [!] CRITICO: Variable group '$vgName' vinculado a Key Vault '$kvName'" -ForegroundColor Red
                        Write-Host "            Variables referenciadas: $($varPairs.Count)" -ForegroundColor Red
                    }
                    elseif ($isHigh) {
                        Write-Host "        [!] ALTO: Variable group '$vgName' con $secretCount variable(s) secreta(s)" -ForegroundColor Yellow
                    }
                }
            }

            # Repositories (inventory)
            $repos = Invoke-DevOpsGet -Uri "https://dev.azure.com/$orgName/$projName/_apis/git/repositories?api-version=7.1"

            if ($repos -and @($repos).Count -gt 0) {
                Write-Host "        [+] Repositorios: $(@($repos).Count)" -ForegroundColor White
                foreach ($repo in @($repos)) {
                    $allRepos.Add([PSCustomObject]@{
                        Organization  = $orgName
                        Project       = $projName
                        RepoName      = $repo.name
                        RepoId        = $repo.id
                        DefaultBranch = $repo.defaultBranch
                        SizeKb        = $repo.size
                        RemoteUrl     = $repo.remoteUrl
                        IsDisabled    = $repo.isDisabled
                    })
                }
            }
        }
    }

    # -- Export CSVs -----------------------------------------------------------

    if ($OutputPath) {
        if ($allServiceConnections.Count -gt 0) {
            try {
                $allServiceConnections.ToArray() | Select-Object Organization, Project, ProjectVisibility,
                    ConnectionName, Type, Scheme, IsShared, IsReady, CreatedBy, AuthParams,
                    HasCriticalFindings, HasHighFindings |
                    Export-Csv -Path (Join-Path $OutputPath "AzRA-AzDevOps-ServiceConnections_$timestamp.csv") `
                    -NoTypeInformation -Encoding UTF8
            } catch { Write-Warning "Could not export ServiceConnections CSV: $_" }
        }

        if ($allVariableGroups.Count -gt 0) {
            try {
                $allVariableGroups.ToArray() | Select-Object Organization, Project,
                    GroupName, Type, IsKeyVaultLinked, KeyVaultName,
                    VariableCount, SecretCount, HasCriticalFindings, HasHighFindings |
                    Export-Csv -Path (Join-Path $OutputPath "AzRA-AzDevOps-VariableGroups_$timestamp.csv") `
                    -NoTypeInformation -Encoding UTF8
            } catch { Write-Warning "Could not export VariableGroups CSV: $_" }
        }

        if ($allAgentPools.Count -gt 0) {
            try {
                $allAgentPools.ToArray() | Export-Csv `
                    -Path (Join-Path $OutputPath "AzRA-AzDevOps-AgentPools_$timestamp.csv") `
                    -NoTypeInformation -Encoding UTF8
            } catch { Write-Warning "Could not export AgentPools CSV: $_" }
        }

        if ($allRepos.Count -gt 0) {
            try {
                $allRepos.ToArray() | Export-Csv `
                    -Path (Join-Path $OutputPath "AzRA-AzDevOps-Repos_$timestamp.csv") `
                    -NoTypeInformation -Encoding UTF8
            } catch { Write-Warning "Could not export Repos CSV: $_" }
        }
    }

    # -- Summary ---------------------------------------------------------------

    $critSC          = ($allServiceConnections | Where-Object { $_.HasCriticalFindings }).Count
    $highSC          = ($allServiceConnections | Where-Object { $_.HasHighFindings }).Count
    $critVG          = ($allVariableGroups     | Where-Object { $_.HasCriticalFindings }).Count
    $highVG          = ($allVariableGroups     | Where-Object { $_.HasHighFindings }).Count
    $selfHostedPools = ($allAgentPools         | Where-Object { $_.IsSelfHosted }).Count

    Write-Host ""
    Write-Host "[*] Reconocimiento Azure DevOps completado" -ForegroundColor Cyan
    if ($critSC -gt 0 -or $highSC -gt 0) {
        Write-Host "  [!] Service connections: $($allServiceConnections.Count) total (Critico: $critSC, Alto: $highSC)" -ForegroundColor $(if ($critSC -gt 0) { 'Red' } else { 'Yellow' })
        $allServiceConnections | Where-Object { $_.HasCriticalFindings } | ForEach-Object {
            Write-Host "    - $($_.Project) / $($_.ConnectionName) [$($_.Type)/$($_.Scheme)]" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  [~] Service connections: $($allServiceConnections.Count)" -ForegroundColor White
    }
    if ($critVG -gt 0 -or $highVG -gt 0) {
        Write-Host "  [!] Variable groups: $($allVariableGroups.Count) total (KV-linked: $critVG, Con secretos: $highVG)" -ForegroundColor $(if ($critVG -gt 0) { 'Red' } else { 'Yellow' })
    }
    else {
        Write-Host "  [~] Variable groups: $($allVariableGroups.Count)" -ForegroundColor White
    }
    if ($selfHostedPools -gt 0) {
        Write-Host "  [!] Agent pools self-hosted: $selfHostedPools" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [~] Agent pools: $($allAgentPools.Count)" -ForegroundColor White
    }
    Write-Host "  [~] Repositorios: $($allRepos.Count)" -ForegroundColor White
    if ($OutputPath) { Write-Host "  [+] Resultados exportados en: $OutputPath" -ForegroundColor White }
    Write-Host ""

    return [PSCustomObject]@{
        ServiceConnections = $allServiceConnections.ToArray()
        VariableGroups     = $allVariableGroups.ToArray()
        AgentPools         = $allAgentPools.ToArray()
        Repositories       = $allRepos.ToArray()
    }
}
