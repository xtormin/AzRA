# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin
# Description: Common helper function for Azure and Microsoft Graph API requests

function Invoke-AzRARequest {
    <#
    .SYNOPSIS
    Common function to make REST API requests to Azure Management or Microsoft Graph APIs

    .DESCRIPTION
    This internal function handles HTTP requests with authentication, error handling, and optional pagination support.

    .PARAMETER Uri
    The API endpoint URI to call

    .PARAMETER AccessToken
    The Bearer token for authentication

    .PARAMETER Method
    HTTP method (GET, POST, etc.). Defaults to GET

    .PARAMETER EnablePagination
    Enable automatic pagination for Microsoft Graph API responses that include @odata.nextLink

    .EXAMPLE
    Invoke-AzRARequest -Uri 'https://graph.microsoft.com/v1.0/users' -AccessToken $token -EnablePagination
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [Parameter(Mandatory=$true)]
        [string]$AccessToken,

        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
        [string]$Method = 'GET',

        [switch]$EnablePagination
    )

    # Build request headers
    $Headers = @{
        'Authorization' = "Bearer $AccessToken"
        'Content-Type' = 'application/json'
    }

    try {
        # Make initial request
        $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method -ErrorAction Stop

        # Handle pagination if enabled and nextLink exists
        if ($EnablePagination -and $Response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $Results = @()
            $Results += $Response.value

            # Follow pagination links
            while ($Response.'@odata.nextLink') {
                Write-Verbose "Following pagination link: $($Response.'@odata.nextLink')"
                $Response = Invoke-RestMethod -Uri $Response.'@odata.nextLink' -Headers $Headers -Method $Method -ErrorAction Stop
                $Results += $Response.value
            }

            return $Results
        }

        # Return value property if it exists, otherwise return full response
        if ($Response.PSObject.Properties.Name -contains 'value') {
            return $Response.value
        } else {
            return $Response
        }
    }
    catch {
        Write-Error "API Request failed for URI '$Uri': $_"
        return $null
    }
}