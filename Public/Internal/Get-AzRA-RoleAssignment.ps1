# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-RoleAssignment {
    <#
    .SYNOPSIS
    Retrieves permissions and role assignments for a specific Azure resource.

    .DESCRIPTION
    This function queries the Azure Management API to retrieve all permissions and role assignments
    for the specified resource path.

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Must have appropriate permissions to read role assignments.

    .PARAMETER ResourcePath
    The full resource path (e.g., /subscriptions/{subId}/resourceGroups/{rg}/providers/{provider}/{resource}).

    .EXAMPLE
    Get-AzRA-RoleAssignment -AccessToken $token -ResourcePath '/subscriptions/xxx/resourceGroups/Test'
    Retrieves permissions for the specified resource group.

    .EXAMPLE
    $path = '/subscriptions/b413826f-108d-4049-8c11-d52d5d348768/resourceGroups/Test/providers/Microsoft.Compute/virtualMachines/infraadmin'
    Get-AzRA-RoleAssignment -AccessToken $token -ResourcePath $path
    Retrieves permissions for a specific virtual machine.

    .OUTPUTS
    System.Object[]
    Returns an array of permission objects with actions and notActions.

    .LINK
    https://learn.microsoft.com/en-us/rest/api/authorization/permissions/list-for-resource
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,

        [Parameter(Mandatory=$true)]
        [string]$ResourcePath
    )

    $Uri = "https://management.azure.com$ResourcePath/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"

    Invoke-AzRARequest `
        -Uri $Uri `
        -AccessToken $AccessToken `
        -Method 'GET'
}