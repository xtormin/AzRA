# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-ResourcesBySubscriptionID {
    <#
    .SYNOPSIS
    Retrieves all Azure resources within a specific subscription.

    .DESCRIPTION
    This function queries the Azure Management API to retrieve all resources (VMs, storage accounts, databases, etc.)
    within the specified subscription.

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Must have appropriate permissions to read resources.

    .PARAMETER SubscriptionID
    The GUID of the Azure subscription to query.

    .EXAMPLE
    Get-AzRA-ResourcesBySubscriptionID -AccessToken $token -SubscriptionID 'b413826f-108d-4049-8c11-d52d5d348768'
    Retrieves all resources in the specified subscription.

    .EXAMPLE
    $resources = Get-AzRA-ResourcesBySubscriptionID -AccessToken $token -SubscriptionID $subId
    $resources | Where-Object {$_.type -eq 'Microsoft.Compute/virtualMachines'}
    Retrieves all resources and filters for virtual machines only.

    .OUTPUTS
    System.Object[]
    Returns an array of resource objects with properties like name, type, location, resourceGroup, etc.

    .LINK
    https://learn.microsoft.com/en-us/rest/api/resources/resources/list
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,

        [Parameter(Mandatory=$true)]
        [string]$SubscriptionID
    )

    $Uri = "https://management.azure.com/subscriptions/$SubscriptionID/resources?api-version=2021-04-01"

    Invoke-AzRARequest `
        -Uri $Uri `
        -AccessToken $AccessToken `
        -Method 'GET'
}