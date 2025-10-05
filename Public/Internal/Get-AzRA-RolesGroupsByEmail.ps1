# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-RolesGroupsByEmail {
    <#
    .SYNOPSIS
    Retrieves all groups and directory roles that a user is a member of.

    .DESCRIPTION
    This function queries the Microsoft Graph API to retrieve all groups and directory roles that the specified user belongs to.
    Automatically handles pagination to retrieve all memberships.

    .PARAMETER AccessToken
    Microsoft Graph API access token (JWT). Must have appropriate permissions like User.Read.All or GroupMember.Read.All.

    .PARAMETER Email
    The user principal name (email) of the user to query.

    .EXAMPLE
    Get-AzRA-RolesGroupsByEmail -AccessToken $token -Email 'user@domain.com'
    Retrieves all groups and roles for the specified user.

    .EXAMPLE
    $groups = Get-AzRA-RolesGroupsByEmail -AccessToken $token -Email 'admin@contoso.com'
    $groups | Where-Object {$_.'@odata.type' -eq '#microsoft.graph.group'}
    Retrieves memberships and filters only groups.

    .OUTPUTS
    System.Object[]
    Returns an array of group and directory role objects.

    .LINK
    https://learn.microsoft.com/en-us/graph/api/user-list-memberof
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,

        [Parameter(Mandatory=$true)]
        [string]$Email
    )

    $Uri = "https://graph.microsoft.com/v1.0/users/$Email/memberOf"

    Invoke-AzRARequest `
        -Uri $Uri `
        -AccessToken $AccessToken `
        -Method 'GET' `
        -EnablePagination
}