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

        # Handle pagination if enabled — supports both Microsoft Graph (@odata.nextLink) and ARM (nextLink)
        if ($EnablePagination) {
            $hasOdataNext = $Response.PSObject.Properties.Name -contains '@odata.nextLink'
            $hasArmNext   = $Response.PSObject.Properties.Name -contains 'nextLink'

            if ($hasOdataNext -or $hasArmNext) {
                $Results = [System.Collections.Generic.List[object]]::new()
                if ($Response.value) { foreach ($item in $Response.value) { $Results.Add($item) } }

                $nextLink = if ($hasOdataNext) { $Response.'@odata.nextLink' } else { $Response.nextLink }

                while ($nextLink) {
                    Write-Verbose "Following pagination link: $nextLink"
                    $Response  = Invoke-RestMethod -Uri $nextLink -Headers $Headers -Method $Method -ErrorAction Stop
                    if ($Response.value) { foreach ($item in $Response.value) { $Results.Add($item) } }
                    $nextLink  = if ($Response.PSObject.Properties.Name -contains '@odata.nextLink') {
                        $Response.'@odata.nextLink'
                    } elseif ($Response.PSObject.Properties.Name -contains 'nextLink') {
                        $Response.nextLink
                    } else {
                        $null
                    }
                }

                return $Results.ToArray()
            }
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