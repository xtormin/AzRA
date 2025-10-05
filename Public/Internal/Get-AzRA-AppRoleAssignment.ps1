# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-AppRoleAssignment {
    <#
    .SYNOPSIS
    Retrieves app role assignments for a specific service principal.

    .DESCRIPTION
    This function queries the Microsoft Graph API to retrieve all app role assignments for a given service principal.
    Automatically handles pagination to retrieve all assignments.

    .PARAMETER AccessToken
    Microsoft Graph API access token (JWT). Must have appropriate permissions like Application.Read.All.

    .PARAMETER ServicePrincipalId
    The Object ID of the service principal to query for role assignments.

    .EXAMPLE
    Get-AzRA-AppRoleAssignment -AccessToken $token -ServicePrincipalId '2830a3fe-846b-4008-b8e5-bbe6255488a8'
    Retrieves all app role assignments for the specified service principal.

    .OUTPUTS
    System.Object[]
    Returns an array of app role assignment objects.

    .LINK
    https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,

        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalId
    )

    $Uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignedTo"

    Invoke-AzRARequest `
        -Uri $Uri `
        -AccessToken $AccessToken `
        -Method 'GET' `
        -EnablePagination
}