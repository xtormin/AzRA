# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-Subscriptions {
    <#
    .SYNOPSIS
    Retrieves all Azure subscriptions accessible with the provided access token.

    .DESCRIPTION
    This function queries the Azure Management API to retrieve all subscriptions that the authenticated user has access to.

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Must have appropriate permissions to list subscriptions.

    .EXAMPLE
    Get-AzRA-Subscriptions -AccessToken $token
    Retrieves all Azure subscriptions accessible with the provided token.

    .EXAMPLE
    $subs = Get-AzRA-Subscriptions -AccessToken $token
    $subs | Select-Object subscriptionId, displayName
    Retrieves subscriptions and displays their ID and display name.

    .OUTPUTS
    System.Object[]
    Returns an array of subscription objects with properties like subscriptionId, displayName, state, etc.

    .LINK
    https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )

    Invoke-AzRARequest `
        -Uri 'https://management.azure.com/subscriptions?api-version=2020-01-01' `
        -AccessToken $AccessToken `
        -Method 'GET'
}