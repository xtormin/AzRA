# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-DeploymentParameterSecrets {
    <#
    .SYNOPSIS
    Audits Azure Resource Group deployment history for sensitive parameters exposed in clear text.

    .DESCRIPTION
    Iterates across all accessible subscriptions (or a specific one), enumerates Resource Group
    deployment histories, and inspects deployment parameter keys for credential-related keywords
    (password, secret, key, token, etc.).

    Filters out SecureString-typed parameters and common false-positive values (null, true, false,
    undefined, none, n/a). Returns findings as PSCustomObjects to the pipeline and optionally
    exports them under a common output folder.

    Requires an active Az session (Connect-AzAccount). Uses automatic retry with linear backoff
    for throttling (HTTP 429) and transient server errors (5xx).

    Required permissions:
      Microsoft.Resources/deployments/read
      Microsoft.Resources/subscriptions/resourceGroups/read

    .PARAMETER SubscriptionId
    Target a single subscription by ID. If omitted, all accessible subscriptions are scanned.

    .PARAMETER Keywords
    Array of keyword strings used to match deployment parameter names (case-insensitive regex).
    Defaults to: password, secret, admin, key, pwd, cred, token, auth.

    .PARAMETER OutputPath
    Folder where all output is saved. The CSV filename is auto-generated with a timestamp:
      <OutputPath>\AzRA-DeploymentSecrets_<yyyyMMdd-HHmm>.csv
    When combined with -DumpRaw, raw JSON files are saved under:
      <OutputPath>\DeploymentTemplatesRawDump\<SubscriptionName>\<ResourceGroupName>\<DeploymentName>.json
    If omitted, findings are only returned to the pipeline (and -DumpRaw is silently skipped).

    .PARAMETER DumpRaw
    If specified, saves the full raw output of Get-AzResourceGroupDeployment for every resource
    group to disk in a hierarchical structure under <OutputPath>\DeploymentTemplatesRawDump\.
    Useful for manual review of complete deployment metadata (Parameters, Outputs,
    OutputResources, TemplateLink, etc.). Each deployment is saved as an individual JSON file.
    Names are sanitized (non-alphanumeric characters replaced with underscores).
    Requires -OutputPath to be set.

    .PARAMETER MaxRetries
    Maximum number of retry attempts on throttling (429) or transient errors (5xx).
    Must be between 1 and 10. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries (multiplied by attempt number).
    Must be between 1 and 60. Default: 5.

    .EXAMPLE
    Get-AzRA-DeploymentSecrets
    Scans all accessible subscriptions and returns findings to the pipeline.

    .EXAMPLE
    Get-AzRA-DeploymentSecrets -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Scans a single subscription.

    .EXAMPLE
    Get-AzRA-DeploymentSecrets -OutputPath 'C:\Reports'
    Scans all subscriptions and exports findings to:
      C:\Reports\AzRA-DeploymentSecrets_<timestamp>.csv

    .EXAMPLE
    Get-AzRA-DeploymentSecrets -OutputPath 'C:\Reports' -DumpRaw
    Full audit: exports findings CSV and dumps all raw deployment JSONs under:
      C:\Reports\AzRA-DeploymentSecrets_<timestamp>.csv
      C:\Reports\DeploymentTemplatesRawDump\<Sub>\<RG>\<Deployment>.json

    .EXAMPLE
    Get-AzRA-DeploymentSecrets | Where-Object { $_.'Grupo de recursos' -eq 'Production' }
    Scans all subscriptions and filters results for a specific resource group.

    .EXAMPLE
    Get-AzRA-DeploymentSecrets -Keywords @('connectionstring','storageaccountkey','sas')
    Scans with custom keyword list.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Each finding contains: 'Nombre suscripcion', 'ID suscripcion', 'Grupo de recursos',
    'Deployment Name', 'Parametros'.

    When -DumpRaw and -OutputPath are active, also writes JSON files to disk at:
      <OutputPath>\DeploymentTemplatesRawDump\<SubscriptionName>\<ResourceGroupName>\<DeploymentName>.json

    .LINK
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azresourcegroupdeployment
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [string[]]$Keywords = @('password', 'secret', 'admin', 'key', 'pwd', 'cred', 'token', 'auth'),

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$DumpRaw,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySec = 5
    )

    $falsePositiveValues = @('null', 'true', 'false', 'undefined', 'none', 'n/a', '')
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Warn if -DumpRaw is requested without -OutputPath (nowhere to write)
    if ($DumpRaw -and -not $OutputPath) {
        Write-Warning "-DumpRaw requires -OutputPath to be set. Raw dump will be skipped."
        $DumpRaw = $false
    }

    # Prepare OutputPath and DumpRaw subfolder early (fail fast before loops)
    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
        }
        catch {
            throw "Cannot create output directory '$OutputPath': $_"
        }

        if ($DumpRaw) {
            $dumpRootPath = Join-Path $OutputPath 'DeploymentTemplatesRawDump'
            try {
                if (-not (Test-Path $dumpRootPath)) {
                    New-Item -ItemType Directory -Force -Path $dumpRootPath -ErrorAction Stop | Out-Null
                }
                Write-Verbose "Raw dump root: $dumpRootPath"
            }
            catch {
                throw "Cannot create raw dump directory '$dumpRootPath': $_"
            }
        }
    }

    # Verify active Az session
    try {
        $currentContext = Get-AzContext -ErrorAction Stop
        if (-not $currentContext) {
            throw "No active Az session found."
        }
        Write-Verbose "Connected as: $($currentContext.Account)"
    }
    catch {
        throw "No active Az session found. Run Connect-AzAccount first. Error: $_"
    }

    # Resolve subscriptions
    if ($SubscriptionId) {
        $subs = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
        if (-not $subs) {
            throw "Subscription not found: $SubscriptionId"
        }
        Write-Verbose "Mode: targeted scan on subscription $($subs.Name)"
    }
    else {
        $subs = Get-AzSubscription -ErrorAction SilentlyContinue
        Write-Verbose "Mode: scanning all accessible subscriptions ($($subs.Count))"
    }

    foreach ($sub in $subs) {
        Write-Verbose "Scanning subscription: $($sub.Name) ($($sub.Id))"

        try {
            Invoke-AzWithRetry -OperationName "Set-AzContext $($sub.Name)" -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec -ScriptBlock {
                Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
            }
        }
        catch {
            Write-Warning "Could not switch to subscription '$($sub.Name)': $_"
            continue
        }

        try {
            $rgs = Invoke-AzWithRetry -OperationName "Get-AzResourceGroup ($($sub.Name))" -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec -ScriptBlock {
                Get-AzResourceGroup -ErrorAction Stop
            }
        }
        catch {
            Write-Warning "Could not list resource groups for '$($sub.Name)': $_"
            continue
        }

        foreach ($rg in $rgs) {
            $rgName = $rg.ResourceGroupName

            try {
                $deployments = Invoke-AzWithRetry -OperationName "Get-AzResourceGroupDeployment ($rgName)" -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec -ScriptBlock {
                    Get-AzResourceGroupDeployment -ResourceGroupName $rgName -ErrorAction Stop
                }
            }
            catch {
                Write-Warning "Could not list deployments for resource group '$rgName': $_"
                continue
            }

            # ── Raw dump ──────────────────────────────────────────────────────
            if ($DumpRaw -and $deployments) {
                $safeSubName = $sub.Name -replace '[^a-zA-Z0-9_\-]', '_'
                $safeRgName  = $rgName  -replace '[^a-zA-Z0-9_\-]', '_'
                $rgDumpDir   = Join-Path (Join-Path $dumpRootPath $safeSubName) $safeRgName

                if (-not (Test-Path $rgDumpDir)) {
                    try {
                        New-Item -ItemType Directory -Force -Path $rgDumpDir -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Warning "Could not create dump directory '$rgDumpDir': $_"
                    }
                }

                if (Test-Path $rgDumpDir) {
                    foreach ($rawDep in $deployments) {
                        $safeDepName = $rawDep.DeploymentName -replace '[^a-zA-Z0-9_\-]', '_'
                        $depFile     = Join-Path $rgDumpDir "$safeDepName.json"
                        try {
                            $rawDep | ConvertTo-Json -Depth 10 |
                                Set-Content -Path $depFile -Encoding UTF8 -ErrorAction Stop
                            Write-Verbose "Dumped: $depFile"
                        }
                        catch {
                            Write-Warning "Could not write dump file '$depFile': $_"
                        }
                    }
                }
            }
            # ── /Raw dump ─────────────────────────────────────────────────────

            foreach ($dep in $deployments) {
                if (-not $dep.Parameters) { continue }

                foreach ($paramKey in $dep.Parameters.Keys) {

                    $match = $Keywords | Where-Object { $paramKey -match $_ }
                    if (-not $match) { continue }

                    $paramObject = $dep.Parameters[$paramKey]
                    $paramValue  = $paramObject.Value
                    $paramType   = $paramObject.Type
                    $valueString = if ($paramValue) { $paramValue.ToString().Trim() } else { '' }

                    if ($paramType -eq 'SecureString')                          { continue }
                    if ([string]::IsNullOrEmpty($valueString))                  { continue }
                    if ($falsePositiveValues -contains $valueString.ToLower())  { continue }

                    $jsonPayload = @{ Name = $paramKey; Value = $paramValue; Type = $paramType }
                    $jsonString  = $jsonPayload | ConvertTo-Json -Compress -Depth 1

                    $obj = [PSCustomObject]@{
                        'Nombre suscripcion' = $sub.Name
                        'ID suscripcion'     = $sub.Id
                        'Grupo de recursos'  = $rgName
                        'Deployment Name'    = $dep.DeploymentName
                        'Parametros'         = $jsonString
                    }

                    Write-Verbose "FINDING: $paramKey in deployment '$($dep.DeploymentName)' ($rgName)"
                    $findings.Add($obj)
                }
            }
        }
    }

    # Export findings CSV with auto-generated timestamp filename
    if ($findings.Count -gt 0 -and $OutputPath) {
        try {
            $timestamp = Get-Date -Format 'yyyyMMdd-HHmm'
            $csvFile   = Join-Path $OutputPath "AzRA-DeploymentSecrets_$timestamp.csv"
            $findings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Verbose "Findings exported to: $csvFile"
        }
        catch {
            Write-Warning "Could not export findings CSV to '$OutputPath': $_"
        }
    }

    return $findings.ToArray()
}
