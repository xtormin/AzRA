# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Request-AzRA-Nonce {
    <#
    .SYNOPSIS
    Requests a nonce value from Azure AD for the specified tenant.

    .DESCRIPTION
    This function requests a nonce (number used once) from Azure AD using the srv_challenge grant type.
    This can be useful for certain authentication flows and security testing scenarios.

    .PARAMETER TenantID
    The Azure AD Tenant ID (GUID) or domain name (e.g., 'contoso.onmicrosoft.com').

    .EXAMPLE
    Request-AzRA-Nonce -TenantID 'contoso.onmicrosoft.com'
    Requests a nonce for the Contoso tenant.

    .EXAMPLE
    $nonce = Request-AzRA-Nonce -TenantID '12345678-1234-1234-1234-123456789abc'
    Requests a nonce using the tenant GUID.

    .OUTPUTS
    System.String
    Returns the nonce value as a string.

    .LINK
    https://login.microsoftonline.com
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TenantID
    )

    $Uri = "https://login.microsoftonline.com/$TenantId/oauth2/token"

    $Body = @{
        "grant_type" = "srv_challenge"
    }

    try {
        $Response = Invoke-RestMethod -Uri $Uri -Method POST -Body $Body -UseBasicParsing -ErrorAction Stop
        return $Response.Nonce
    }
    catch {
        Write-Error "Failed to request nonce for tenant '$TenantID': $_"
        return $null
    }
}