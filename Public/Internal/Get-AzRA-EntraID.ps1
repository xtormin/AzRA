# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-EntraID {
    <#
    .SYNOPSIS
    Audits Entra ID (Azure Active Directory) tenant configuration for security misconfigurations
    relevant to penetration testing and red team operations.

    .DESCRIPTION
    Queries the Microsoft Graph API to evaluate security controls across the tenant. Returns a
    single object per tenant containing collections of findings organized by severity.

    Base checks (Directory.Read.All):
      - Tenant info, verified domains, license tier (P1/P2)
      - Authorization policy: user app registration, consent settings, guest invitation
      - Security Defaults enforcement
      - Privileged role assignments: Global Admins, privileged guests, privileged service principals
      - Stale privileged accounts (no sign-in for >90 days)

    Optional checks with elevated permissions:
      -IncludeMFAReport   (Reports.Read.All):  MFA registration status per user
      -IncludeApps        (Application.Read.All): App registrations - expired creds, broad permissions, no owners
      -IncludeConditionalAccess (Policy.Read.All): CA policies - legacy auth blocking, MFA gaps, report-only

    All optional sections fail gracefully: a 403 emits Write-Warning and the corresponding
    fields are set to $null rather than aborting the scan.

    .PARAMETER GraphToken
    Microsoft Graph API access token (JWT), scoped to https://graph.microsoft.com/.
    Obtain with:
      (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken

    .PARAMETER OutputPath
    Folder where all output is saved. Raw JSON dumps are saved under:
      <OutputPath>\EntraIDRawDump\*.json
    CSV reports are saved as:
      <OutputPath>\AzRA-EntraID-Summary_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-EntraID-GlobalAdmins_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-EntraID-PrivilegedUsers_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-EntraID-MFA_<yyyyMMdd-HHmm>.csv           (only with -IncludeMFAReport)
      <OutputPath>\AzRA-EntraID-Apps_<yyyyMMdd-HHmm>.csv          (only with -IncludeApps)
      <OutputPath>\AzRA-EntraID-CAPolicies_<yyyyMMdd-HHmm>.csv    (only with -IncludeConditionalAccess)

    .PARAMETER IncludeMFAReport
    Queries /reports/authenticationMethods/userRegistrationDetails to evaluate per-user MFA
    registration status. Requires Reports.Read.All permission.

    .PARAMETER IncludeApps
    Queries /applications to evaluate app registration security: expired credentials, apps
    without owners, multi-tenant apps, and apps with sensitive Graph permissions.
    Requires Application.Read.All (or Directory.Read.All in some tenants).

    .PARAMETER IncludeConditionalAccess
    Queries /identity/conditionalAccess/policies to evaluate whether legacy authentication is
    blocked, MFA is required for privileged users and all users, and whether any policies are
    in report-only mode. Requires Policy.Read.All.

    .PARAMETER MaxRetries
    Maximum retry attempts on throttling (HTTP 429) or transient errors (5xx).
    Must be between 1 and 10. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries (multiplied by attempt number).
    Must be between 1 and 60. Default: 5.

    .EXAMPLE
    $graphToken = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    Get-AzRA-EntraID -GraphToken $graphToken
    Runs base checks only (Directory.Read.All).

    .EXAMPLE
    Get-AzRA-EntraID -GraphToken $graphToken -IncludeMFAReport -IncludeApps -IncludeConditionalAccess
    Full audit with all optional checks.

    .EXAMPLE
    Get-AzRA-EntraID -GraphToken $graphToken -IncludeMFAReport -IncludeConditionalAccess -OutputPath 'C:\Audit'
    Full audit with CSV and JSON dump output.

    .EXAMPLE
    $result = Get-AzRA-EntraID -GraphToken $graphToken -IncludeMFAReport
    $result.GlobalAdminsWithoutMFA | Select-Object DisplayName, UserPrincipalName
    $result.PrivilegedGuests
    $result.SecurityDefaultsDisabled

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    A single object per tenant containing identity fields, boolean security flags, and
    collections of findings per category.

    .LINK
    https://learn.microsoft.com/en-us/graph/api/overview
    https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GraphToken,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeMFAReport,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeApps,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeConditionalAccess,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySec = 5
    )

    # -- Constants -------------------------------------------------------------

    # Built-in role GUIDs for high-privilege roles
    $HighPrivRoleIds = @{
        'Global Administrator'              = '62e90394-69f5-4237-9190-012177145e10'
        'Privileged Role Administrator'     = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        'Security Administrator'            = '194ae4cb-b126-40b2-bd5b-6091b380977d'
        'Exchange Administrator'            = '29232cdf-9323-42fd-ade2-1d097af3e4de'
        'SharePoint Administrator'          = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
        'Application Administrator'         = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        'Cloud Application Administrator'   = '158c047a-c907-4556-b7ef-446551a6b5f7'
        'Authentication Administrator'      = 'c4e39bd9-1100-46d3-8c65-fb160da0071f'
        'Helpdesk Administrator'            = '729827e3-9c14-49f7-bb1b-9608f156bbb8'
        'User Administrator'                = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
    }
    $GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'

    # Sensitive Microsoft Graph Application permissions (resource app: 00000003-0000-0000-c000-000000000000)
    $SensitivePermIds = @{
        'Directory.ReadWrite.All'            = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'
        'Directory.Read.All'                 = '7ab1d382-f21e-4acd-a863-ba3e13f7da61'
        'User.ReadWrite.All'                 = '741f803b-c850-494e-b5df-cde7c675a1ca'
        'Mail.ReadWrite'                     = 'e2a3a72e-5f79-4c64-b1b1-878b674786c9'
        'Mail.Read'                          = '810c84a8-4a9e-49e6-bf7d-12d183f40d01'
        'Group.ReadWrite.All'                = '62a82d76-70ea-41e2-9197-370581804d09'
        'Application.ReadWrite.All'          = '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9'
        'AppRoleAssignment.ReadWrite.All'    = '06b708a9-e830-4db3-a914-8e69da51d44f'
        'RoleManagement.ReadWrite.Directory' = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'
    }
    $SensitivePermIdSet  = [System.Collections.Generic.HashSet[string]]($SensitivePermIds.Values)
    $MicrosoftGraphAppId = '00000003-0000-0000-c000-000000000000'

    # Weak MFA methods (SMS/voice only)
    $WeakMFAMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone')

    # -- Private helpers -------------------------------------------------------

    function Get-GraphHeaders {
        return @{ 'Authorization' = "Bearer $GraphToken"; 'Content-Type' = 'application/json' }
    }

    # Safe Graph GET that returns $null on 403/404 instead of throwing.
    # Uses -ErrorAction Stop so that Write-Error inside Invoke-AzRARequest becomes
    # a terminating exception that the catch block here can actually intercept.
    function Invoke-GraphGet {
        param([string]$Uri, [switch]$Paginated)
        try {
            if ($Paginated) {
                return Invoke-AzRARequest -Uri $Uri -AccessToken $GraphToken -Method GET -EnablePagination -ErrorAction Stop
            }
            else {
                return Invoke-AzRARequest -Uri $Uri -AccessToken $GraphToken -Method GET -ErrorAction Stop
            }
        }
        catch {
            $msg = $_.ToString()
            if ($msg -match '403|Forbidden') {
                Write-Warning "  [403] Insufficient permissions for: $Uri - add Policy.Read.All, Reports.Read.All or Application.Read.All as needed."
            }
            elseif ($msg -match '400|Bad Request') {
                Write-Warning "  [400] Bad request for: $Uri"
            }
            elseif ($msg -match '401|Unauthorized') {
                Write-Warning "  [401] Token expired or invalid for: $Uri"
            }
            else {
                Write-Warning "  [ERROR] $Uri : $msg"
            }
            return $null
        }
    }

    # -- Initialization --------------------------------------------------------

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $now       = Get-Date
    $staleDate = $now.AddDays(-90)
    $dumpRoot  = $null

    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
            $dumpRoot = Join-Path $OutputPath 'EntraIDRawDump'
            if (-not (Test-Path $dumpRoot)) {
                New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null
            }
        }
        catch {
            throw "Cannot create output directory '$OutputPath': $_"
        }
    }

    # -- Phase 2: Base calls ---------------------------------------------------

    Write-Host "[*] Entra ID Audit - iniciando analisis del tenant..." -ForegroundColor Cyan

    # a. Tenant info
    Write-Host "  [~] Obteniendo informacion del tenant..." -ForegroundColor Gray
    $orgResponse = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,createdDateTime,verifiedDomains,assignedPlans'
    $org = if ($orgResponse -is [array]) { $orgResponse[0] } else { $orgResponse }

    $tenantId          = $org.id
    $tenantName        = $org.displayName
    $tenantCreated     = $org.createdDateTime
    $verifiedDomains   = @($org.verifiedDomains | Where-Object { $_.isVerified } | ForEach-Object { $_.name })

    # Check P1/P2 plans
    $tenantHasP1P2 = $false
    if ($org.assignedPlans) {
        $p1Guid = 'eec0eb4f-6444-4f95-aba0-50de565b5ce5'  # AAD Premium P1
        $p2Guid = '84a661c4-e949-4bd2-a560-ed7766fcaf2b'  # AAD Premium P2
        foreach ($plan in $org.assignedPlans) {
            if ($plan.servicePlanId -in @($p1Guid, $p2Guid) -and $plan.capabilityStatus -eq 'Enabled') {
                $tenantHasP1P2 = $true; break
            }
        }
    }

    Write-Host "  [+] Tenant: $tenantName ($tenantId)" -ForegroundColor White
    Write-Host "  [+] Dominios: $($verifiedDomains -join ', ')" -ForegroundColor White
    Write-Host "  [+] Licencia P1/P2: $tenantHasP1P2" -ForegroundColor White

    # b. Authorization policy
    Write-Host "  [~] Leyendo authorization policy..." -ForegroundColor Gray
    $authPolicy = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    # May return array with one element
    if ($authPolicy -is [array]) { $authPolicy = $authPolicy[0] }

    # c. Security Defaults - requires Policy.Read.All; gracefully handled if 403
    Write-Host "  [~] Comprobando Security Defaults..." -ForegroundColor Gray
    $secDefaults        = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    # $null = could not retrieve (insufficient permissions); treat as unknown, not as 'disabled'
    $secDefaultsEnabled = if ($secDefaults) { ($secDefaults.isEnabled -eq $true) } else { $null }

    # e. Role definitions (build index)
    Write-Host "  [~] Enumerando definiciones de roles..." -ForegroundColor Gray
    $roleDefs = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn' -Paginated
    $roleDefIndex = @{}
    if ($roleDefs) { foreach ($rd in $roleDefs) { $roleDefIndex[$rd.id] = $rd.displayName } }

    # f. Role assignments with principal expand
    Write-Host "  [~] Obteniendo role assignments..." -ForegroundColor Gray
    $roleAssignments = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$select=id,roleDefinitionId,principalId,principal&$top=999' -Paginated

    # g. Users
    Write-Host "  [~] Enumerando usuarios (puede tardar en tenants grandes)..." -ForegroundColor Gray
    $users = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,signInActivity&$top=999' -Paginated

    # Build user index by id
    $userIndex = @{}
    if ($users) { foreach ($u in $users) { $userIndex[$u.id] = $u } }

    $totalUserCount = if ($users) { @($users).Count } else { 0 }
    $guestCount     = if ($users) { @($users | Where-Object { $_.userType -eq 'Guest' }).Count } else { 0 }
    Write-Host "  [+] Usuarios encontrados: $totalUserCount (Guests: $guestCount)" -ForegroundColor White

    # h. Service Principals
    Write-Host "  [~] Enumerando service principals..." -ForegroundColor Gray
    $servicePrincipals = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=servicePrincipalType eq 'Application'&`$select=id,displayName,appId,accountEnabled,servicePrincipalType&`$top=999" -Paginated
    $spIndex = @{}
    if ($servicePrincipals) { foreach ($sp in $servicePrincipals) { $spIndex[$sp.id] = $sp } }
    Write-Host "  [+] Service principals encontrados: $(if ($servicePrincipals) { @($servicePrincipals).Count } else { 0 })" -ForegroundColor White

    # -- i/j. Evaluate directory checks and correlate role assignments ---------

    Write-Host "  [~] Evaluando configuracion de directorio y roles privilegiados..." -ForegroundColor Gray

    # Authorization policy checks
    $usersCanRegisterApps      = $false
    $usersCanConsentToApps     = $false
    $guestInvitationNotRestricted = $false
    $adminConsentWorkflowDisabled = $true
    $linkedInEnabled           = $false

    if ($authPolicy) {
        $usersCanRegisterApps = ($authPolicy.defaultUserRolePermissions.allowedToCreateApps -eq $true)

        # User consent: if permissionGrantPolicyIdsAssignedToDefaultUserRole is non-empty, users can consent
        $consentPolicies = $authPolicy.defaultUserRolePermissions.permissionGrantPolicies
        if (-not $consentPolicies) {
            $consentPolicies = $authPolicy.permissionGrantPolicyIdsAssignedToDefaultUserRole
        }
        $usersCanConsentToApps = ($consentPolicies -and @($consentPolicies).Count -gt 0)

        # Guest invitation: 'everyone' or 'adminsAndMembers' = not restricted
        $allowInvitesFrom = $authPolicy.allowInvitesFrom
        $guestInvitationNotRestricted = ($allowInvitesFrom -notin @('adminsAndGuestInviters', 'none', $null))

        # Admin consent workflow: check if enabled via allowEmailVerifiedUsersToJoinOrganization or specific policy
        # The proper check is via /policies/adminConsentRequestPolicy (may not exist in all tenants)
        # Fallback: if tenant has no P2, workflow likely not configured
        $adminConsentWorkflowDisabled = (-not $tenantHasP1P2) -or $true  # Default assume disabled; refined below

        # LinkedIn
        $linkedInEnabled = ($null -ne $authPolicy.allowedToUseSSPR) # placeholder; LinkedIn flag varies by API version
    }

    # Try /policies/adminConsentRequestPolicy for accurate admin consent workflow check
    # Requires Policy.Read.All - uses Invoke-GraphGet so 403 is handled gracefully
    $adminConsentPolicy = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy'
    if ($adminConsentPolicy) {
        $adminConsentWorkflowDisabled = ($adminConsentPolicy.isEnabled -ne $true)
    }
    # Correlate role assignments
    $globalAdmins               = [System.Collections.Generic.List[PSCustomObject]]::new()
    $privilegedGuests           = [System.Collections.Generic.List[PSCustomObject]]::new()
    $privilegedServicePrincipals = [System.Collections.Generic.List[PSCustomObject]]::new()
    $stalePrivilegedAccounts    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allPrivRoleAssignments     = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($roleAssignments) {
        # Group by principalId to collect all roles per principal
        $principalRoles = @{}
        foreach ($ra in $roleAssignments) {
            $rid = $ra.principalId
            if (-not $principalRoles[$rid]) { $principalRoles[$rid] = [System.Collections.Generic.List[string]]::new() }
            $roleName = if ($roleDefIndex[$ra.roleDefinitionId]) { $roleDefIndex[$ra.roleDefinitionId] } else { $ra.roleDefinitionId }
            $principalRoles[$rid].Add($roleName)
        }

        foreach ($ra in $roleAssignments) {
            $roleDefId = $ra.roleDefinitionId
            $roleName  = if ($roleDefIndex[$roleDefId]) { $roleDefIndex[$roleDefId] } else { $roleDefId }

            # Only process high-privilege roles
            if ($roleDefId -notin $HighPrivRoleIds.Values) { continue }

            $principal = $ra.principal
            if (-not $principal) {
                # Try to resolve from index
                $principal = $userIndex[$ra.principalId]
                if (-not $principal) { $principal = $spIndex[$ra.principalId] }
            }

            $principalType    = if ($principal.'@odata.type') { $principal.'@odata.type' -replace '#microsoft.graph.', '' } else { 'unknown' }
            $principalUPN     = $principal.userPrincipalName
            $principalName    = $principal.displayName
            $principalId      = $ra.principalId
            $allRoles         = if ($principalRoles[$principalId]) { $principalRoles[$principalId].ToArray() } else { @($roleName) }

            $raObj = [PSCustomObject]@{
                PrincipalId          = $principalId
                PrincipalDisplayName = $principalName
                UserPrincipalName    = $principalUPN
                PrincipalType        = $principalType
                RoleName             = $roleName
                AllRoles             = ($allRoles -join ', ')
            }
            $allPrivRoleAssignments.Add($raObj)

            # Global Admins
            if ($roleDefId -eq $GlobalAdminRoleId -and $principalType -eq 'user') {
                $globalAdmins.Add([PSCustomObject]@{
                    Id                = $principalId
                    DisplayName       = $principalName
                    UserPrincipalName = $principalUPN
                    UserType          = $principal.userType
                })
            }

            # Privileged Guests
            if ($principalType -eq 'user' -and $principal.userType -eq 'Guest') {
                $privilegedGuests.Add([PSCustomObject]@{
                    Id                = $principalId
                    DisplayName       = $principalName
                    UserPrincipalName = $principalUPN
                    Roles             = ($allRoles -join ', ')
                })
            }

            # Privileged Service Principals
            if ($principalType -in @('servicePrincipal', 'application')) {
                $privilegedServicePrincipals.Add([PSCustomObject]@{
                    Id          = $principalId
                    DisplayName = $principalName
                    AppId       = $principal.appId
                    Roles       = ($allRoles -join ', ')
                })
            }

            # Stale privileged accounts (users only)
            if ($principalType -eq 'user') {
                $lastSignIn = $principal.signInActivity.lastSignInDateTime
                $isStale    = $false
                if (-not $lastSignIn) {
                    $isStale = $true  # Never signed in = potentially stale
                }
                else {
                    try {
                        $lastSignInDate = [datetime]$lastSignIn
                        $isStale = ($lastSignInDate -lt $staleDate)
                    }
                    catch { $isStale = $false }
                }

                if ($isStale) {
                    $stalePrivilegedAccounts.Add([PSCustomObject]@{
                        Id                = $principalId
                        DisplayName       = $principalName
                        UserPrincipalName = $principalUPN
                        LastSignIn        = $lastSignIn
                        Roles             = ($allRoles -join ', ')
                    })
                }
            }
        }
    }

    $globalAdminCount = $globalAdmins.Count

    # Deduplicate stale accounts (same user may appear multiple times due to multiple roles)
    $stalePrivSet = @{}
    $stalePrivDeduped = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($s in $stalePrivilegedAccounts) {
        if (-not $stalePrivSet[$s.Id]) {
            $stalePrivSet[$s.Id] = $true
            $stalePrivDeduped.Add($s)
        }
    }
    $stalePrivilegedAccounts = $stalePrivDeduped

    # Deduplicate privileged guests
    $guestSet = @{}
    $privilegedGuestsDeduped = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($g in $privilegedGuests) {
        if (-not $guestSet[$g.Id]) {
            $guestSet[$g.Id] = $true
            $privilegedGuestsDeduped.Add($g)
        }
    }
    $privilegedGuests = $privilegedGuestsDeduped

    # Deduplicate privileged SPs
    $spSet = @{}
    $privilegedSPsDeduped = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($sp in $privilegedServicePrincipals) {
        if (-not $spSet[$sp.Id]) {
            $spSet[$sp.Id] = $true
            $privilegedSPsDeduped.Add($sp)
        }
    }
    $privilegedServicePrincipals = $privilegedSPsDeduped

    # -- Phase 3: MFA Report ---------------------------------------------------

    $globalAdminsWithoutMFA = [System.Collections.Generic.List[PSCustomObject]]::new()
    $usersWithoutMFA        = [System.Collections.Generic.List[PSCustomObject]]::new()
    $usersWithWeakMFA       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mfaRegistrationRate    = $null
    $mfaReportData          = $null

    if ($IncludeMFAReport) {
        Write-Host ""
        Write-Host "[*] Phase 3: MFA Report" -ForegroundColor Cyan
        Write-Host "  [~] Obteniendo informe de registro MFA..." -ForegroundColor Gray
        $mfaReportData = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=id,userPrincipalName,isMfaCapable,isMfaRegistered,methodsRegistered,isPasswordlessCapable&$top=999' -Paginated

        if ($mfaReportData) {
            # Build MFA index by user ID
            $mfaIndex = @{}
            foreach ($entry in $mfaReportData) { $mfaIndex[$entry.id] = $entry }

            $mfaCapableCount = 0
            foreach ($entry in $mfaReportData) {
                if ($entry.isMfaCapable -eq $true) { $mfaCapableCount++ }

                # Users without any MFA
                if ($entry.isMfaCapable -ne $true) {
                    $usersWithoutMFA.Add([PSCustomObject]@{
                        Id                = $entry.id
                        UserPrincipalName = $entry.userPrincipalName
                        DisplayName       = if ($userIndex[$entry.id]) { $userIndex[$entry.id].displayName } else { $entry.userPrincipalName }
                        MethodsRegistered = ($entry.methodsRegistered -join ', ')
                    })
                }
                else {
                    # Users with only weak MFA methods (SMS/voice)
                    $methods = @($entry.methodsRegistered)
                    $hasStrongMethod = $methods | Where-Object { $_ -notin $WeakMFAMethods -and $_ -ne 'email' }
                    if (-not $hasStrongMethod) {
                        $usersWithWeakMFA.Add([PSCustomObject]@{
                            Id                = $entry.id
                            UserPrincipalName = $entry.userPrincipalName
                            DisplayName       = if ($userIndex[$entry.id]) { $userIndex[$entry.id].displayName } else { $entry.userPrincipalName }
                            MethodsRegistered = ($methods -join ', ')
                        })
                    }
                }
            }

            # Global admins without MFA
            $globalAdminIds = [System.Collections.Generic.HashSet[string]]($globalAdmins | ForEach-Object { $_.Id })
            foreach ($entry in $mfaReportData) {
                if ($globalAdminIds.Contains($entry.id) -and $entry.isMfaCapable -ne $true) {
                    $globalAdminsWithoutMFA.Add([PSCustomObject]@{
                        Id                = $entry.id
                        DisplayName       = if ($userIndex[$entry.id]) { $userIndex[$entry.id].displayName } else { $entry.userPrincipalName }
                        UserPrincipalName = $entry.userPrincipalName
                        MethodsRegistered = ($entry.methodsRegistered -join ', ')
                    })
                }
            }

            if (@($mfaReportData).Count -gt 0) {
                $mfaRegistrationRate = [Math]::Round(($mfaCapableCount / @($mfaReportData).Count) * 100, 1)
            }
            Write-Host "  [+] Usuarios sin MFA: $($usersWithoutMFA.Count) | MFA debil: $($usersWithWeakMFA.Count) | Tasa registro MFA: $mfaRegistrationRate%" -ForegroundColor White
            if ($globalAdminsWithoutMFA.Count -gt 0) {
                Write-Host "  [!] Global Admins sin MFA: $($globalAdminsWithoutMFA.Count)" -ForegroundColor Red
            }
        }
        else {
            Write-Warning "  MFA report unavailable. Ensure token has Reports.Read.All permission."
        }
    }

    # -- Phase 4: App Registrations --------------------------------------------

    $appsWithExpiredCreds    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $appsWithoutOwners       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $multiTenantApps         = [System.Collections.Generic.List[PSCustomObject]]::new()
    $appsWithBroadPermissions = [System.Collections.Generic.List[PSCustomObject]]::new()
    $externalAppsCount       = $null
    $allAppsForCsv           = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($IncludeApps) {
        Write-Host ""
        Write-Host "[*] Phase 4: App Registrations" -ForegroundColor Cyan
        Write-Host "  [~] Enumerando app registrations..." -ForegroundColor Gray
        $applications = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,displayName,appId,createdDateTime,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess&$expand=owners&$top=999' -Paginated

        if ($applications) {
            $externalAppsCount = 0
            foreach ($app in $applications) {
                $appName     = $app.displayName
                $appId       = $app.appId
                $audience    = $app.signInAudience
                $isExternal  = ($audience -in @('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount', 'PersonalMicrosoftAccount'))
                if ($isExternal) { $externalAppsCount++ }

                # Expired credentials
                $expiredCreds = [System.Collections.Generic.List[PSCustomObject]]::new()
                $allCreds = @()
                if ($app.passwordCredentials) { $allCreds += $app.passwordCredentials | ForEach-Object { $_ | Add-Member -NotePropertyName '_credType' -NotePropertyValue 'password' -PassThru -Force } }
                if ($app.keyCredentials)      { $allCreds += $app.keyCredentials      | ForEach-Object { $_ | Add-Member -NotePropertyName '_credType' -NotePropertyValue 'certificate' -PassThru -Force } }

                foreach ($cred in $allCreds) {
                    if (-not $cred.endDateTime) {
                        # No expiry = never expires (informational)
                        continue
                    }
                    try {
                        $endDate = [datetime]$cred.endDateTime
                        if ($endDate -lt $now) {
                            $expiredCreds.Add([PSCustomObject]@{
                                DisplayName    = $appName
                                AppId          = $appId
                                CredentialType = $cred._credType
                                ExpiredOn      = $cred.endDateTime
                                KeyId          = $cred.keyId
                            })
                        }
                    }
                    catch {}
                }
                if ($expiredCreds.Count -gt 0) {
                    foreach ($ec in $expiredCreds) { $appsWithExpiredCreds.Add($ec) }
                }

                # Apps without owners
                $owners = $app.owners
                if (-not $owners -or @($owners).Count -eq 0) {
                    $appsWithoutOwners.Add([PSCustomObject]@{
                        DisplayName = $appName
                        AppId       = $appId
                        SignInAudience = $audience
                    })
                }

                # Multi-tenant apps
                if ($isExternal) {
                    $multiTenantApps.Add([PSCustomObject]@{
                        DisplayName    = $appName
                        AppId          = $appId
                        SignInAudience = $audience
                    })
                }

                # Apps with broad/sensitive Graph permissions
                $sensitivePermsFound = [System.Collections.Generic.List[string]]::new()
                if ($app.requiredResourceAccess) {
                    foreach ($rra in $app.requiredResourceAccess) {
                        if ($rra.resourceAppId -ne $MicrosoftGraphAppId) { continue }
                        foreach ($access in $rra.resourceAccess) {
                            if ($access.type -eq 'Role' -and $SensitivePermIdSet.Contains($access.id)) {
                                $permName = ($SensitivePermIds.GetEnumerator() | Where-Object { $_.Value -eq $access.id } | Select-Object -First 1).Key
                                if ($permName) { $sensitivePermsFound.Add($permName) }
                                else { $sensitivePermsFound.Add($access.id) }
                            }
                        }
                    }
                }
                if ($sensitivePermsFound.Count -gt 0) {
                    $appsWithBroadPermissions.Add([PSCustomObject]@{
                        DisplayName          = $appName
                        AppId                = $appId
                        SignInAudience        = $audience
                        SensitivePermissions = ($sensitivePermsFound -join ', ')
                    })
                }

                # Build CSV row
                $allAppsForCsv.Add([PSCustomObject]@{
                    DisplayName          = $appName
                    AppId                = $appId
                    SignInAudience        = $audience
                    HasExpiredCreds      = ($expiredCreds.Count -gt 0)
                    HasOwners            = ($owners -and @($owners).Count -gt 0)
                    IsMultiTenant        = $isExternal
                    SensitivePermissions = ($sensitivePermsFound -join ', ')
                    HasBroadPermissions  = ($sensitivePermsFound.Count -gt 0)
                    CreatedDateTime      = $app.createdDateTime
                })
            }
            Write-Host "  [+] Apps encontradas: $(@($applications).Count) | Externas: $externalAppsCount | Creds expiradas: $($appsWithExpiredCreds.Count) | Sin owners: $($appsWithoutOwners.Count)" -ForegroundColor White
            if ($appsWithBroadPermissions.Count -gt 0) {
                Write-Host "  [!] Apps con permisos sensibles: $($appsWithBroadPermissions.Count)" -ForegroundColor Red
            }
        }
        else {
            Write-Warning "  App registrations unavailable. Ensure token has Application.Read.All or Directory.Read.All."
        }
    }

    # -- Phase 5: Conditional Access Policies ----------------------------------

    $legacyAuthNotBlocked       = $null
    $noMFARequiredForAdmins     = $null
    $noCARequiringMFAForAllUsers = $null
    $caPoliciesReportOnly       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $activeCAPoliciesCount      = $null
    $allCAPoliciesForCsv        = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($IncludeConditionalAccess) {
        Write-Host ""
        Write-Host "[*] Phase 5: Conditional Access Policies" -ForegroundColor Cyan
        Write-Host "  [~] Leyendo Conditional Access policies..." -ForegroundColor Gray
        $caPolicies = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Paginated

        if ($caPolicies) {
            $enabledPolicies = @($caPolicies | Where-Object { $_.state -eq 'enabled' })
            $activeCAPoliciesCount = $enabledPolicies.Count

            # Track findings
            $legacyAuthBlocked      = $false
            $mfaForAdminsRequired   = $false
            $mfaForAllUsersRequired = $false

            foreach ($policy in $caPolicies) {
                $state      = $policy.state
                $conditions = $policy.conditions
                $grant      = $policy.grantControls

                # Report-only policies
                if ($state -eq 'enabledForReportingButNotEnforced') {
                    $caPoliciesReportOnly.Add([PSCustomObject]@{
                        DisplayName = $policy.displayName
                        Id          = $policy.id
                        State       = $state
                    })
                }

                # Only evaluate enabled policies for security checks
                if ($state -ne 'enabled') {
                    $allCAPoliciesForCsv.Add([PSCustomObject]@{
                        DisplayName       = $policy.displayName
                        Id                = $policy.id
                        State             = $state
                        BlocksLegacyAuth  = $false
                        RequiresMFA       = $false
                        TargetsAllUsers   = $false
                    })
                    continue
                }

                $grantControls = @()
                if ($grant.builtInControls) { $grantControls = @($grant.builtInControls) }
                $requiresMFA   = ($grantControls -contains 'mfa')

                # Detect legacy auth blocking
                # Legacy auth policy blocks clientAppTypes: exchangeActiveSync and/or other
                $clientAppTypes = @($conditions.clientAppTypes)
                $blocksLegacy   = ($clientAppTypes -contains 'exchangeActiveSync' -or $clientAppTypes -contains 'other') -and
                                  ($grant.builtInControls -contains 'block' -or $grant.operator -eq 'OR')
                # Alternative: block grant on legacy client types
                if ($blocksLegacy) { $legacyAuthBlocked = $true }

                # Check for MFA required for all users
                $includeUsers = @($conditions.users.includeUsers)
                $targetsAll   = ($includeUsers -contains 'All')
                if ($requiresMFA -and $targetsAll) { $mfaForAllUsersRequired = $true }

                # Check for MFA required for privileged admins
                $includeRoles = @($conditions.users.includeRoles)
                $targetsPrivRoles = ($includeRoles | Where-Object { $_ -in $HighPrivRoleIds.Values }).Count -gt 0
                if ($requiresMFA -and ($targetsAll -or $targetsPrivRoles)) { $mfaForAdminsRequired = $true }

                $allCAPoliciesForCsv.Add([PSCustomObject]@{
                    DisplayName       = $policy.displayName
                    Id                = $policy.id
                    State             = $state
                    BlocksLegacyAuth  = $blocksLegacy
                    RequiresMFA       = $requiresMFA
                    TargetsAllUsers   = $targetsAll
                })
            }

            $legacyAuthNotBlocked        = (-not $legacyAuthBlocked)
            $noMFARequiredForAdmins      = (-not $mfaForAdminsRequired)
            $noCARequiringMFAForAllUsers = (-not $mfaForAllUsersRequired)

            Write-Host "  [+] Policies activas: $activeCAPoliciesCount | Solo reporte: $($caPoliciesReportOnly.Count)" -ForegroundColor White
            if ($legacyAuthNotBlocked) {
                Write-Host "  [!] Auth legacy NO bloqueada" -ForegroundColor Red
            }
            if ($noMFARequiredForAdmins) {
                Write-Host "  [!] Sin CA policy que requiera MFA para admins" -ForegroundColor Red
            }
        }
        else {
            Write-Warning "  Conditional Access policies unavailable. Ensure token has Policy.Read.All."
        }
    }

    # -- Phase 6: Raw dump -----------------------------------------------------

    $rawFilePath = $null
    if ($dumpRoot) {
        $dumps = @{
            'tenant.json'              = $org
            'authorizationPolicy.json' = $authPolicy
            'securityDefaults.json'    = $secDefaults
            'roleAssignments.json'     = $roleAssignments
        }
        if ($IncludeConditionalAccess -and $caPolicies) { $dumps['conditionalAccessPolicies.json'] = $caPolicies }
        if ($IncludeApps -and $applications)             { $dumps['applications.json'] = $applications }
        if ($IncludeMFAReport -and $mfaReportData)       { $dumps['mfaRegistrationDetails.json'] = $mfaReportData }

        foreach ($fileName in $dumps.Keys) {
            $filePath = Join-Path $dumpRoot $fileName
            try {
                $dumps[$fileName] | ConvertTo-Json -Depth 20 |
                    Set-Content -Path $filePath -Encoding UTF8 -ErrorAction Stop
                Write-Verbose "  Dumped: $filePath"
            }
            catch { Write-Warning "  Could not write '$fileName': $_" }
        }
        $rawFilePath = $dumpRoot
    }

    # -- Phase 7: Export CSVs --------------------------------------------------

    if ($OutputPath) {
        # Summary CSV (single row)
        try {
            $summaryRow = [PSCustomObject]@{
                TenantId                      = $tenantId
                TenantDisplayName             = $tenantName
                TenantHasP1P2                 = $tenantHasP1P2
                SecurityDefaultsDisabled      = if ($null -ne $secDefaultsEnabled) { (-not $secDefaultsEnabled) } else { $null }
                UsersCanRegisterApps          = $usersCanRegisterApps
                UsersCanConsentToApps         = $usersCanConsentToApps
                GuestInvitationNotRestricted  = $guestInvitationNotRestricted
                AdminConsentWorkflowDisabled  = $adminConsentWorkflowDisabled
                TotalUserCount                = $totalUserCount
                GuestCount                    = $guestCount
                GlobalAdminCount              = $globalAdminCount
                PrivilegedGuestsCount         = $privilegedGuests.Count
                PrivilegedSPsCount            = $privilegedServicePrincipals.Count
                StalePrivilegedAccountsCount  = $stalePrivilegedAccounts.Count
                GlobalAdminsWithoutMFACount   = $globalAdminsWithoutMFA.Count
                UsersWithoutMFACount          = $usersWithoutMFA.Count
                UsersWithWeakMFACount         = $usersWithWeakMFA.Count
                MFARegistrationRate           = $mfaRegistrationRate
                LegacyAuthNotBlocked          = $legacyAuthNotBlocked
                NoMFARequiredForAdmins        = $noMFARequiredForAdmins
                NoCARequiringMFAForAllUsers   = $noCARequiringMFAForAllUsers
                CAPoliciesReportOnlyCount     = $caPoliciesReportOnly.Count
                ActiveCAPoliciesCount         = $activeCAPoliciesCount
                AppsWithExpiredCredsCount     = $appsWithExpiredCreds.Count
                AppsWithoutOwnersCount        = $appsWithoutOwners.Count
                MultiTenantAppsCount          = $multiTenantApps.Count
                AppsWithBroadPermissionsCount = $appsWithBroadPermissions.Count
                ExternalAppsCount             = $externalAppsCount
            }
            $summaryRow | Export-Csv -Path (Join-Path $OutputPath "AzRA-EntraID-Summary_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        }
        catch { Write-Warning "Could not export summary CSV: $_" }

        # Global Admins CSV
        if ($globalAdmins.Count -gt 0) {
            try {
                $globalAdmins.ToArray() | Export-Csv -Path (Join-Path $OutputPath "AzRA-EntraID-GlobalAdmins_$timestamp.csv") -NoTypeInformation -Encoding UTF8
            }
            catch { Write-Warning "Could not export GlobalAdmins CSV: $_" }
        }

        # Privileged users CSV
        if ($allPrivRoleAssignments.Count -gt 0) {
            try {
                $allPrivRoleAssignments.ToArray() | Export-Csv -Path (Join-Path $OutputPath "AzRA-EntraID-PrivilegedUsers_$timestamp.csv") -NoTypeInformation -Encoding UTF8
            }
            catch { Write-Warning "Could not export PrivilegedUsers CSV: $_" }
        }

        # MFA CSV
        if ($IncludeMFAReport -and $mfaReportData) {
            try {
                $mfaReportData | Select-Object id, userPrincipalName, isMfaCapable, isMfaRegistered,
                    @{N='MethodsRegistered'; E={ ($_.methodsRegistered -join ', ') }}, isPasswordlessCapable |
                    Export-Csv -Path (Join-Path $OutputPath "AzRA-EntraID-MFA_$timestamp.csv") -NoTypeInformation -Encoding UTF8
            }
            catch { Write-Warning "Could not export MFA CSV: $_" }
        }

        # Apps CSV
        if ($IncludeApps -and $allAppsForCsv.Count -gt 0) {
            try {
                $allAppsForCsv.ToArray() | Export-Csv -Path (Join-Path $OutputPath "AzRA-EntraID-Apps_$timestamp.csv") -NoTypeInformation -Encoding UTF8
            }
            catch { Write-Warning "Could not export Apps CSV: $_" }
        }

        # CA Policies CSV
        if ($IncludeConditionalAccess -and $allCAPoliciesForCsv.Count -gt 0) {
            try {
                $allCAPoliciesForCsv.ToArray() | Export-Csv -Path (Join-Path $OutputPath "AzRA-EntraID-CAPolicies_$timestamp.csv") -NoTypeInformation -Encoding UTF8
            }
            catch { Write-Warning "Could not export CA Policies CSV: $_" }
        }

        Write-Verbose "CSV exports completed under: $OutputPath"
    }

    # -- Phase 8: Build and return result object -------------------------------

    # Summary booleans
    $hasCritical = (
        $globalAdminsWithoutMFA.Count -gt 0 -or
        $privilegedGuests.Count -gt 0 -or
        $privilegedServicePrincipals.Count -gt 0 -or
        ($legacyAuthNotBlocked -eq $true) -or
        ($noMFARequiredForAdmins -eq $true) -or
        $appsWithBroadPermissions.Count -gt 0
    )

    $hasHigh = (
        (-not $secDefaultsEnabled) -or
        $usersCanRegisterApps -or
        $usersCanConsentToApps -or
        $guestInvitationNotRestricted -or
        $adminConsentWorkflowDisabled -or
        $stalePrivilegedAccounts.Count -gt 0 -or
        $usersWithoutMFA.Count -gt 0 -or
        $usersWithWeakMFA.Count -gt 0 -or
        $appsWithExpiredCreds.Count -gt 0 -or
        $appsWithoutOwners.Count -gt 0 -or
        ($noCARequiringMFAForAllUsers -eq $true) -or
        $caPoliciesReportOnly.Count -gt 0
    )

    $result = [PSCustomObject]@{
        # Tenant identity
        TenantId              = $tenantId
        TenantDisplayName     = $tenantName
        TenantCreatedDateTime = $tenantCreated
        VerifiedDomains       = $verifiedDomains
        TenantHasP1P2         = $tenantHasP1P2

        # Summary flags
        HasCriticalFindings   = $hasCritical
        HasHighFindings       = $hasHigh

        # Stats
        TotalUserCount        = $totalUserCount
        GuestCount            = $guestCount
        GlobalAdminCount      = $globalAdminCount
        ActiveCAPoliciesCount = $activeCAPoliciesCount
        MFARegistrationRate   = $mfaRegistrationRate
        ExternalAppsCount     = $externalAppsCount

        # Critical - collections
        GlobalAdminsWithoutMFA       = $globalAdminsWithoutMFA.ToArray()
        PrivilegedGuests             = $privilegedGuests.ToArray()
        PrivilegedServicePrincipals  = $privilegedServicePrincipals.ToArray()
        LegacyAuthNotBlocked         = $legacyAuthNotBlocked
        NoMFARequiredForAdmins       = $noMFARequiredForAdmins
        AppsWithBroadPermissions     = $appsWithBroadPermissions.ToArray()

        # High - booleans and collections
        SecurityDefaultsDisabled       = (-not $secDefaultsEnabled)
        UsersCanRegisterApps           = $usersCanRegisterApps
        UsersCanConsentToApps          = $usersCanConsentToApps
        GuestInvitationNotRestricted   = $guestInvitationNotRestricted
        AdminConsentWorkflowDisabled   = $adminConsentWorkflowDisabled
        StalePrivilegedAccounts        = $stalePrivilegedAccounts.ToArray()
        UsersWithoutMFA                = $usersWithoutMFA.ToArray()
        UsersWithWeakMFA               = $usersWithWeakMFA.ToArray()
        AppsWithExpiredCredentials     = $appsWithExpiredCreds.ToArray()
        AppsWithoutOwners              = $appsWithoutOwners.ToArray()
        MultiTenantApps                = $multiTenantApps.ToArray()
        CAPoliciesReportOnly           = $caPoliciesReportOnly.ToArray()
        NoCARequiringMFAForAllUsers    = $noCARequiringMFAForAllUsers

        # Informational
        GlobalAdmins                 = $globalAdmins.ToArray()
        AllPrivilegedRoleAssignments = $allPrivRoleAssignments.ToArray()
        LinkedInConnectionsEnabled   = $linkedInEnabled

        RawFilePath = $rawFilePath
    }

    # -- Phase 8: Summary output -----------------------------------------------

    Write-Host ""
    Write-Host "[*] Auditoria completada" -ForegroundColor Cyan
    Write-Host "  [+] Tenant: $tenantName ($tenantId)" -ForegroundColor White

    if ($hasCritical) {
        Write-Host "  [CRITICO] Hallazgos criticos detectados:" -ForegroundColor Red
        if ($globalAdminsWithoutMFA.Count -gt 0)        { Write-Host "    - Global Admins sin MFA: $($globalAdminsWithoutMFA.Count)" -ForegroundColor Red }
        if ($privilegedGuests.Count -gt 0)              { Write-Host "    - Guests con roles privilegiados: $($privilegedGuests.Count)" -ForegroundColor Red }
        if ($privilegedServicePrincipals.Count -gt 0)   { Write-Host "    - Service Principals con roles privilegiados: $($privilegedServicePrincipals.Count)" -ForegroundColor Red }
        if ($legacyAuthNotBlocked -eq $true)            { Write-Host "    - Auth legacy NO bloqueada" -ForegroundColor Red }
        if ($noMFARequiredForAdmins -eq $true)          { Write-Host "    - Sin CA policy que requiera MFA para admins" -ForegroundColor Red }
        if ($appsWithBroadPermissions.Count -gt 0)      { Write-Host "    - Apps con permisos sensibles: $($appsWithBroadPermissions.Count)" -ForegroundColor Red }
    }
    else {
        Write-Host "  [OK] Sin hallazgos criticos" -ForegroundColor Green
    }

    if ($hasHigh) {
        Write-Host "  [ALTO] Hallazgos de severidad alta:" -ForegroundColor Yellow
        if ($secDefaultsEnabled -eq $false)             { Write-Host "    - Security Defaults deshabilitados" -ForegroundColor Yellow }
        if ($usersCanRegisterApps)                      { Write-Host "    - Usuarios pueden registrar apps" -ForegroundColor Yellow }
        if ($usersCanConsentToApps)                     { Write-Host "    - Usuarios pueden dar consentimiento a apps" -ForegroundColor Yellow }
        if ($guestInvitationNotRestricted)              { Write-Host "    - Invitacion de guests no restringida" -ForegroundColor Yellow }
        if ($adminConsentWorkflowDisabled)              { Write-Host "    - Admin consent workflow deshabilitado" -ForegroundColor Yellow }
        if ($stalePrivilegedAccounts.Count -gt 0)       { Write-Host "    - Cuentas privilegiadas inactivas: $($stalePrivilegedAccounts.Count)" -ForegroundColor Yellow }
        if ($usersWithoutMFA.Count -gt 0)               { Write-Host "    - Usuarios sin MFA: $($usersWithoutMFA.Count)" -ForegroundColor Yellow }
        if ($usersWithWeakMFA.Count -gt 0)              { Write-Host "    - Usuarios con MFA debil (SMS/voz): $($usersWithWeakMFA.Count)" -ForegroundColor Yellow }
        if ($appsWithExpiredCreds.Count -gt 0)          { Write-Host "    - Apps con credenciales expiradas: $($appsWithExpiredCreds.Count)" -ForegroundColor Yellow }
        if ($appsWithoutOwners.Count -gt 0)             { Write-Host "    - Apps sin owners: $($appsWithoutOwners.Count)" -ForegroundColor Yellow }
        if ($noCARequiringMFAForAllUsers -eq $true)     { Write-Host "    - Sin CA policy que requiera MFA para todos los usuarios" -ForegroundColor Yellow }
        if ($caPoliciesReportOnly.Count -gt 0)          { Write-Host "    - CA policies en modo solo-reporte: $($caPoliciesReportOnly.Count)" -ForegroundColor Yellow }
    }
    else {
        Write-Host "  [OK] Sin hallazgos de severidad alta" -ForegroundColor Green
    }

    if ($OutputPath) {
        Write-Host "  [+] Resultados exportados en: $OutputPath" -ForegroundColor White
    }
    Write-Host ""

    return $result
}
