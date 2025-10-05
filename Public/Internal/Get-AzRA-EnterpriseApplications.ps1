# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-EnterpriseApplications {
    <#
    .SYNOPSIS
    Retrieves all enterprise applications (application registrations) from Microsoft Graph API.

    .DESCRIPTION
    This function queries the Microsoft Graph API to retrieve all application registrations in the tenant.
    Automatically handles pagination to retrieve all applications.

    .PARAMETER AccessToken
    Microsoft Graph API access token (JWT). Must have appropriate permissions like Application.Read.All.

    .EXAMPLE
    Get-AzRA-EnterpriseApplications -AccessToken $token
    Retrieves all enterprise applications from the tenant.

    .EXAMPLE
    $apps = Get-AzRA-EnterpriseApplications -AccessToken $token
    $apps | Select-Object displayName, appId
    Retrieves all applications and displays their names and IDs.

    .OUTPUTS
    System.Object[]
    Returns an array of application objects with properties like displayName, appId, publisherDomain, etc.

    .LINK
    https://learn.microsoft.com/en-us/graph/api/application-list
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )

    Invoke-AzRARequest `
        -Uri 'https://graph.microsoft.com/v1.0/applications' `
        -AccessToken $AccessToken `
        -Method 'GET' `
        -EnablePagination
}