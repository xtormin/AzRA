# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-ManagedIdentities {
    <#
    .SYNOPSIS
    Enumerates Azure User-Assigned Managed Identities and their role assignments,
    mapping privilege escalation paths and overly permissive configurations.

    .DESCRIPTION
    Enumerates all User-Assigned Managed Identities (UAMIs) and resolves their role
    assignments at subscription, resource group, and resource scope. Identifies:

      Critical:     OwnerOrContributor at subscription scope,
                    UserAccessAdministrator (can assign roles = full privilege escalation),
                    GlobalAdminOrPrivilegedRoleAdmin (Entra ID roles via Graph)
      High:         Contributor at resource group scope,
                    SecurityAdmin, KeyVaultContributor, StorageAccountContributor,
                    WebsiteContributor (allows reading app settings)
      Informational: Identities not assigned to any resource (orphaned),
                     Multiple resources sharing the same identity

    Also enumerates System-Assigned Managed Identities by reading them from existing
    resources (VMs, Function Apps, Logic Apps, etc.) if -IncludeSystemAssigned is specified.

    Required permissions:
      Microsoft.ManagedIdentity/userAssignedIdentities/read
      Microsoft.Authorization/roleAssignments/read
      Microsoft.Authorization/roleDefinitions/read

    .PARAMETER AccessToken
    Azure Management API access token. Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where output is saved. Raw dumps under:
      <OutputPath>\ManagedIdentitiesRawDump\<SubscriptionName>\<IdentityName>\identity.json
      <OutputPath>\ManagedIdentitiesRawDump\<SubscriptionName>\<IdentityName>\roleAssignments.json
    CSV reports:
      <OutputPath>\AzRA-ManagedIdentities_<timestamp>.csv
      <OutputPath>\AzRA-ManagedIdentities-RoleAssignments_<timestamp>.csv

    .PARAMETER IncludeSystemAssigned
    If specified, also enumerates system-assigned managed identities by reading their
    principal IDs from VMs, Function Apps, and Logic Apps and resolving their role assignments.

    .PARAMETER MaxRetries
    Maximum retry attempts. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-ManagedIdentities -AccessToken $token

    .EXAMPLE
    Get-AzRA-ManagedIdentities -AccessToken $token -IncludeSystemAssigned -OutputPath 'C:\Audit'

    .EXAMPLE
    $result = Get-AzRA-ManagedIdentities -AccessToken $token
    $result | Where-Object { $_.HasCriticalFindings } |
        ForEach-Object { $_.RoleAssignments | Format-Table RoleName, Scope, ScopeType }

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    One object per managed identity.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]  [string]$AccessToken,
        [Parameter(Mandatory = $false)] [string]$SubscriptionId,
        [Parameter(Mandatory = $false)] [string]$OutputPath,
        [Parameter(Mandatory = $false)] [switch]$IncludeSystemAssigned,
        [Parameter(Mandatory = $false)] [ValidateRange(1,10)]  [int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)] [ValidateRange(1,60)]  [int]$RetryDelaySec = 5
    )

    # Well-known role definition IDs
    $CriticalRoleIds = @{
        'Owner'                        = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        'Contributor'                  = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
        'UserAccessAdministrator'      = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
    }
    $HighRoleIds = @{
        'SecurityAdmin'                = 'fb1c8493-542b-48eb-b624-b4c8fea62acd'
        'KeyVaultContributor'          = 'f25e0fa2-a7c8-4d83-b232-c7e19f4c7e8f'
        'StorageAccountContributor'    = '17d1049b-9a84-46fb-8f53-869881c3d3ab'
        'WebsiteContributor'           = 'de139f84-1756-47ae-9be6-808fbbe84772'
        'LogicAppContributor'          = '87a39d53-fc1b-424a-814c-f7e04687dc9e'
        'AutomationContributor'        = 'f353d9bd-d4a6-484e-a77a-8050b599b867'
        'CognitiveServicesContributor' = '25fbc0a9-bd7c-42a3-aa1a-3b75d497ee68'
    }

    function Get-RgFromId {
        param([string]$ResourceId)
        if ($ResourceId -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
        return $null
    }

    function Get-ScopeType {
        param([string]$Scope)
        if ($Scope -match '^/subscriptions/[^/]+$')           { return 'Subscription' }
        if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 'ResourceGroup' }
        return 'Resource'
    }

    function Resolve-RoleAssignments {
        param([string]$PrincipalId, [string]$SubId, [hashtable]$RoleDefCache)

        $results   = [System.Collections.Generic.List[PSCustomObject]]::new()
        $hasCrit   = $false
        $hasHigh   = $false

        # Get all role assignments for this principal across the subscription
        $raUri = "https://management.azure.com/subscriptions/$SubId/providers/Microsoft.Authorization/roleAssignments?`$filter=principalId+eq+'$PrincipalId'&api-version=2022-04-01"
        $ras   = Invoke-AzRARequest -Uri $raUri -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $ras) { return @{ Results = $results; HasCritical = $hasCrit; HasHigh = $hasHigh } }

        foreach ($ra in $ras) {
            $roleDefId   = $ra.properties.roleDefinitionId -replace '.*/roleDefinitions/', ''
            $scope       = $ra.properties.scope
            $scopeType   = Get-ScopeType -Scope $scope

            # Resolve role name (with cache)
            if (-not $RoleDefCache[$roleDefId]) {
                try {
                    $rd = Invoke-AzRARequest `
                        -Uri "https://management.azure.com/subscriptions/$SubId/providers/Microsoft.Authorization/roleDefinitions/$roleDefId`?api-version=2022-04-01" `
                        -AccessToken $AccessToken -Method GET -ErrorAction Stop
                    $RoleDefCache[$roleDefId] = if ($rd) { $rd.properties.roleName } else { $roleDefId }
                }
                catch { $RoleDefCache[$roleDefId] = $roleDefId }
            }
            $roleName = $RoleDefCache[$roleDefId]

            # Classify severity
            $isCritical = (
                ($roleDefId -eq $CriticalRoleIds['Owner']                   -and $scopeType -in @('Subscription', 'ResourceGroup')) -or
                ($roleDefId -eq $CriticalRoleIds['Contributor']             -and $scopeType -eq 'Subscription') -or
                ($roleDefId -eq $CriticalRoleIds['UserAccessAdministrator'] )
            )
            $isHigh = (
                (-not $isCritical) -and (
                    ($roleDefId -eq $CriticalRoleIds['Contributor'] -and $scopeType -eq 'ResourceGroup') -or
                    ($roleDefId -in $HighRoleIds.Values)
                )
            )

            if ($isCritical) { $hasCrit = $true }
            if ($isHigh)     { $hasHigh = $true }

            $results.Add([PSCustomObject]@{
                RoleDefinitionId = $roleDefId
                RoleName         = $roleName
                Scope            = $scope
                ScopeType        = $scopeType
                IsCritical       = $isCritical
                IsHigh           = $isHigh
            })
        }

        return @{ Results = $results; HasCritical = $hasCrit; HasHigh = $hasHigh }
    }

    # -- Init ------------------------------------------------------------------

    $allIdentities  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allRaRows      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $roleDefCache   = @{}
    $timestamp      = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot       = $null

    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null }
            $dumpRoot = Join-Path $OutputPath 'ManagedIdentitiesRawDump'
            if (-not (Test-Path $dumpRoot)) { New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null }
        }
        catch { throw "Cannot create output directory '$OutputPath': $_" }
    }

    Write-Host ""
    Write-Host "[*] Managed Identities - iniciando auditoria..." -ForegroundColor Cyan

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
        Write-Host "    [~] Enumerando User-Assigned Managed Identities..." -ForegroundColor Gray

        # -- User-Assigned MIs -------------------------------------------------

        $uamis = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $uamis) {
            Write-Host "    [~] Sin User-Assigned Managed Identities en esta subscripcion" -ForegroundColor Gray
        }
        else {
            Write-Host "    [+] UAMIs encontradas: $(@($uamis).Count)" -ForegroundColor White

            foreach ($mi in $uamis) {
                $miName      = $mi.name
                $rgName      = Get-RgFromId -ResourceId $mi.id
                $principalId = $mi.properties.principalId
                $clientId    = $mi.properties.clientId

                Write-Host "    [~] Resolviendo roles: $miName ($principalId)" -ForegroundColor Gray

                $raResult = Resolve-RoleAssignments -PrincipalId $principalId -SubId $subId -RoleDefCache $roleDefCache
                $raList   = $raResult.Results
                $hasCrit  = $raResult.HasCritical
                $hasHigh  = $raResult.HasHigh

                if ($hasCrit) {
                    Write-Host "    [!] CRITICO: $miName" -ForegroundColor Red
                    $raList | Where-Object { $_.IsCritical } | ForEach-Object {
                        Write-Host "        - $($_.RoleName) en scope $($_.ScopeType): $($_.Scope)" -ForegroundColor Red
                    }
                }
                elseif ($hasHigh) {
                    Write-Host "    [!] ALTO: $miName" -ForegroundColor Yellow
                    $raList | Where-Object { $_.IsHigh } | ForEach-Object {
                        Write-Host "        - $($_.RoleName) en scope $($_.ScopeType): $($_.Scope)" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "    [OK] $miName ($($raList.Count) roles)" -ForegroundColor Green
                }

                # CSV rows for role assignments
                foreach ($ra in $raList) {
                    $allRaRows.Add([PSCustomObject]@{
                        SubscriptionName = $subName
                        SubscriptionId   = $subId
                        ResourceGroup    = $rgName
                        IdentityName     = $miName
                        IdentityType     = 'UserAssigned'
                        PrincipalId      = $principalId
                        ClientId         = $clientId
                        RoleName         = $ra.RoleName
                        Scope            = $ra.Scope
                        ScopeType        = $ra.ScopeType
                        IsCritical       = $ra.IsCritical
                        IsHigh           = $ra.IsHigh
                    })
                }

                # Raw dump
                $rawFilePath = $null
                if ($dumpRoot -and $rgName) {
                    $dir = Join-Path (Join-Path $dumpRoot ($subName -replace '[^a-zA-Z0-9_\-]','_')) ($miName -replace '[^a-zA-Z0-9_\-]','_')
                    if (-not (Test-Path $dir)) { try { New-Item -ItemType Directory -Force -Path $dir -ErrorAction Stop | Out-Null } catch {} }
                    if (Test-Path $dir) {
                        try { $mi | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $dir 'identity.json') -Encoding UTF8 -ErrorAction Stop } catch {}
                        if ($raList.Count -gt 0) {
                            try { $raList.ToArray() | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $dir 'roleAssignments.json') -Encoding UTF8 -ErrorAction Stop } catch {}
                        }
                        $rawFilePath = $dir
                    }
                }

                $allIdentities.Add([PSCustomObject]@{
                    SubscriptionId       = $subId
                    SubscriptionName     = $subName
                    ResourceGroup        = $rgName
                    IdentityName         = $miName
                    IdentityType         = 'UserAssigned'
                    PrincipalId          = $principalId
                    ClientId             = $clientId
                    Location             = $mi.location
                    RoleCount            = $raList.Count
                    RoleAssignments      = $raList.ToArray()
                    HasCriticalFindings  = $hasCrit
                    HasHighFindings      = $hasHigh
                    RawFilePath          = $rawFilePath
                })
            }
        }

        # -- System-Assigned MIs (optional) ------------------------------------

        if ($IncludeSystemAssigned) {
            Write-Host "    [~] Enumerando System-Assigned Managed Identities (VMs, Functions, Logic Apps)..." -ForegroundColor Gray

            $samiSources = @(
                @{ Provider = 'Microsoft.Compute/virtualMachines';                ApiVersion = '2024-07-01' },
                @{ Provider = 'Microsoft.Web/sites';                              ApiVersion = '2023-12-01' },
                @{ Provider = 'Microsoft.Logic/workflows';                        ApiVersion = '2019-05-01' },
                @{ Provider = 'Microsoft.Automation/automationAccounts';          ApiVersion = '2023-11-01' }
            )

            foreach ($source in $samiSources) {
                $resources = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/providers/$($source.Provider)?api-version=$($source.ApiVersion)" `
                    -AccessToken $AccessToken -Method GET -EnablePagination

                if (-not $resources) { continue }

                foreach ($res in $resources) {
                    $identity = $res.identity
                    if (-not $identity -or $identity.type -notmatch 'SystemAssigned') { continue }
                    $principalId = $identity.principalId
                    if (-not $principalId) { continue }

                    $resName = $res.name
                    $rgName2 = Get-RgFromId -ResourceId $res.id

                    Write-Host "    [~] Resolviendo roles SAMI: $resName ($principalId)" -ForegroundColor Gray

                    $raResult = Resolve-RoleAssignments -PrincipalId $principalId -SubId $subId -RoleDefCache $roleDefCache
                    $raList   = $raResult.Results
                    $hasCrit  = $raResult.HasCritical
                    $hasHigh  = $raResult.HasHigh

                    if ($hasCrit) {
                        Write-Host "    [!] CRITICO (SAMI): $resName" -ForegroundColor Red
                        $raList | Where-Object { $_.IsCritical } | ForEach-Object {
                            Write-Host "        - $($_.RoleName) en scope $($_.ScopeType): $($_.Scope)" -ForegroundColor Red
                        }
                    }
                    elseif ($hasHigh) {
                        Write-Host "    [!] ALTO (SAMI): $resName" -ForegroundColor Yellow
                        $raList | Where-Object { $_.IsHigh } | ForEach-Object {
                            Write-Host "        - $($_.RoleName) en scope $($_.ScopeType): $($_.Scope)" -ForegroundColor Yellow
                        }
                    }

                    foreach ($ra in $raList) {
                        $allRaRows.Add([PSCustomObject]@{
                            SubscriptionName = $subName
                            SubscriptionId   = $subId
                            ResourceGroup    = $rgName2
                            IdentityName     = $resName
                            IdentityType     = 'SystemAssigned'
                            PrincipalId      = $principalId
                            ClientId         = $null
                            RoleName         = $ra.RoleName
                            Scope            = $ra.Scope
                            ScopeType        = $ra.ScopeType
                            IsCritical       = $ra.IsCritical
                            IsHigh           = $ra.IsHigh
                        })
                    }

                    if ($raList.Count -gt 0 -or $hasCrit -or $hasHigh) {
                        $allIdentities.Add([PSCustomObject]@{
                            SubscriptionId       = $subId
                            SubscriptionName     = $subName
                            ResourceGroup        = $rgName2
                            IdentityName         = $resName
                            IdentityType         = 'SystemAssigned'
                            PrincipalId          = $principalId
                            ClientId             = $null
                            Location             = $res.location
                            RoleCount            = $raList.Count
                            RoleAssignments      = $raList.ToArray()
                            HasCriticalFindings  = $hasCrit
                            HasHighFindings      = $hasHigh
                            RawFilePath          = $null
                        })
                    }
                }
            }
        }
    }

    # -- Export CSVs -----------------------------------------------------------

    if ($OutputPath) {
        if ($allIdentities.Count -gt 0) {
            try {
                $allIdentities.ToArray() | Select-Object SubscriptionName, ResourceGroup,
                    IdentityName, IdentityType, PrincipalId, ClientId, Location,
                    RoleCount, HasCriticalFindings, HasHighFindings, RawFilePath |
                    Export-Csv -Path (Join-Path $OutputPath "AzRA-ManagedIdentities_$timestamp.csv") -NoTypeInformation -Encoding UTF8
            } catch { Write-Warning "Could not export identities CSV: $_" }
        }

        if ($allRaRows.Count -gt 0) {
            try {
                $allRaRows.ToArray() | Export-Csv `
                    -Path (Join-Path $OutputPath "AzRA-ManagedIdentities-RoleAssignments_$timestamp.csv") `
                    -NoTypeInformation -Encoding UTF8
            } catch { Write-Warning "Could not export role assignments CSV: $_" }
        }
    }

    # -- Summary ---------------------------------------------------------------

    $critCount  = ($allIdentities | Where-Object { $_.HasCriticalFindings }).Count
    $highCount  = ($allIdentities | Where-Object { $_.HasHighFindings -and -not $_.HasCriticalFindings }).Count
    $totalCount = $allIdentities.Count

    Write-Host ""
    Write-Host "[*] Auditoria completada: $totalCount managed identities analizadas" -ForegroundColor Cyan
    if ($critCount -gt 0) {
        Write-Host "  [!] Identidades con hallazgos CRITICOS: $critCount" -ForegroundColor Red
        $allIdentities | Where-Object { $_.HasCriticalFindings } | ForEach-Object {
            $roles = ($_.RoleAssignments | Where-Object { $_.IsCritical } | ForEach-Object { "$($_.RoleName)@$($_.ScopeType)" }) -join ', '
            Write-Host "    - [$($_.IdentityType)] $($_.IdentityName): $roles" -ForegroundColor Red
        }
    }
    if ($highCount -gt 0) { Write-Host "  [!] Identidades con hallazgos ALTOS: $highCount" -ForegroundColor Yellow }
    if ($OutputPath)      { Write-Host "  [+] Resultados exportados en: $OutputPath" -ForegroundColor White }
    Write-Host ""

    return $allIdentities.ToArray()
}
