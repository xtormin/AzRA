# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin
# Description: Generic function to make custom API requests to Azure or Microsoft Graph APIs.

function Invoke-AzRA-APIRequest {
    <#
    .SYNOPSIS
    Makes a custom GET request to any Azure Management or Microsoft Graph API endpoint.

    .DESCRIPTION
    This is a generic wrapper function that allows making custom API requests to any Azure or Microsoft Graph endpoint.
    Useful for exploring APIs or making requests to endpoints not covered by other specific functions.

    .PARAMETER AccessToken
    Access token (JWT) for authentication. Must be valid for the target API (Azure Management or Microsoft Graph).

    .PARAMETER Uri
    The full API endpoint URI to call.

    .PARAMETER EnablePagination
    Enable automatic pagination for responses that include @odata.nextLink (Microsoft Graph).

    .EXAMPLE
    Invoke-AzRA-APIRequest -AccessToken $token -Uri 'https://management.azure.com/subscriptions?api-version=2020-01-01'
    Makes a custom request to list subscriptions.

    .EXAMPLE
    Invoke-AzRA-APIRequest -AccessToken $token -Uri 'https://graph.microsoft.com/v1.0/groups' -EnablePagination
    Makes a custom request to Microsoft Graph with automatic pagination.

    .OUTPUTS
    System.Object
    Returns the API response, typically an array of objects.

    .LINK
    https://learn.microsoft.com/en-us/rest/api/azure/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,

        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [switch]$EnablePagination
    )

    Invoke-AzRARequest `
        -Uri $Uri `
        -AccessToken $AccessToken `
        -Method 'GET' `
        -EnablePagination:$EnablePagination
}