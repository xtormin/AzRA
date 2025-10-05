# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-Users {
    <#
    .SYNOPSIS
    Retrieves all users from Microsoft Graph API.

    .DESCRIPTION
    This function queries the Microsoft Graph API to retrieve all user accounts in the tenant.
    Automatically handles pagination to retrieve all users if there are more than 100.

    .PARAMETER AccessToken
    Microsoft Graph API access token (JWT). Must have appropriate permissions like User.Read.All.

    .EXAMPLE
    Get-AzRA-Users -AccessToken $token
    Retrieves all users from the tenant.

    .EXAMPLE
    $users = Get-AzRA-Users -AccessToken $token
    $users | Where-Object {$_.userPrincipalName -like "*admin*"}
    Retrieves all users and filters for admin accounts.

    .OUTPUTS
    System.Object[]
    Returns an array of user objects with properties like userPrincipalName, displayName, mail, etc.

    .LINK
    https://learn.microsoft.com/en-us/graph/api/user-list
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )

    Invoke-AzRARequest `
        -Uri 'https://graph.microsoft.com/v1.0/users' `
        -AccessToken $AccessToken `
        -Method 'GET' `
        -EnablePagination
}