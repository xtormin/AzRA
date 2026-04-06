# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-AutomationRunbooks {
    <#
    .SYNOPSIS
    Downloads and optionally scans Azure Automation Runbooks for secrets across all accessible subscriptions.

    .DESCRIPTION
    Enumerates all Azure Automation Accounts across accessible subscriptions (or a specific one),
    downloads the source code of every published Runbook, and optionally scans the content for
    hardcoded credentials or sensitive strings.

    Returns one PSCustomObject per Runbook to the pipeline. When -OutputPath is specified, saves
    Runbook content to a hierarchical folder structure and exports findings to CSV.

    Required permissions:
      Microsoft.Automation/automationAccounts/read
      Microsoft.Automation/automationAccounts/runbooks/read
      Microsoft.Automation/automationAccounts/runbooks/content/read

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription by ID. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where all output is saved. Runbook files are saved under:
      <OutputPath>\AutomationRunbooks\<SubscriptionName>\<AutomationAccount>\<RunbookName>.<ext>
    CSV reports are saved as:
      <OutputPath>\AzRA-AutomationRunbooks_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-AutomationRunbooks-Secrets_<yyyyMMdd-HHmm>.csv  (only if -ScanSecrets)
    If omitted, findings are only returned to the pipeline.

    .PARAMETER ScanSecrets
    If specified, scans each Runbook's content for hardcoded credentials or sensitive strings
    matching the Keywords list. Findings are included in the pipeline objects and exported
    to a separate CSV when -OutputPath is also set.

    .PARAMETER Keywords
    Keywords used to detect sensitive assignments in Runbook content (case-insensitive).
    Matches patterns like: password = "value", token: 'value', apikey="value".
    Defaults to a broad list of credential-related terms.

    .PARAMETER MaxRetries
    Maximum retry attempts on throttling (HTTP 429) or transient errors (5xx).
    Must be between 1 and 10. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries (multiplied by attempt number).
    Must be between 1 and 60. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-AutomationRunbooks -AccessToken $token
    Enumerates all Runbooks across all subscriptions and returns metadata to the pipeline.

    .EXAMPLE
    Get-AzRA-AutomationRunbooks -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Scans a single subscription.

    .EXAMPLE
    Get-AzRA-AutomationRunbooks -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets
    Downloads all Runbooks and scans for secrets. Saves files and CSV reports under C:\Audit.

    .EXAMPLE
    Get-AzRA-AutomationRunbooks -AccessToken $token -ScanSecrets |
        Where-Object { $_.HasSecrets } |
        Select-Object RunbookName, AutomationAccount, SecretFindings
    Returns only Runbooks that contain potential secrets.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Each object contains: SubscriptionId, SubscriptionName, AutomationAccount, ResourceGroup,
    RunbookName, RunbookType, RunbookState, LastModified, ContentSizeBytes, FilePath,
    SecretFindings, HasSecrets.

    .LINK
    https://learn.microsoft.com/en-us/rest/api/automation/runbook
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$ScanSecrets,

        [Parameter(Mandatory = $false)]
        [string[]]$Keywords = @(
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'credential', 'cred', 'apikey', 'api_key', 'connectionstring',
            'connstr', 'sas', 'auth', 'access_key', 'client_secret'
        ),

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySec = 5
    )

    $allRunbooks  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSecrets   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp    = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot     = $null

    # Prepare output directory early (fail fast)
    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
            $dumpRoot = Join-Path $OutputPath 'AutomationRunbooks'
            if (-not (Test-Path $dumpRoot)) {
                New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null
            }
        }
        catch {
            throw "Cannot create output directory '$OutputPath': $_"
        }
    }

    # Resolve subscriptions
    if ($SubscriptionId) {
        $subs = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$SubscriptionId`?api-version=2022-12-01" `
            -AccessToken $AccessToken -Method GET
        if (-not $subs) { throw "Subscription not found: $SubscriptionId" }
        $subs = @($subs)
    }
    else {
        $subs = Invoke-AzRARequest `
            -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' `
            -AccessToken $AccessToken -Method GET -EnablePagination
    }

    Write-Verbose "Subscriptions to scan: $($subs.Count)"

    foreach ($sub in $subs) {
        $subId   = $sub.subscriptionId
        $subName = $sub.displayName
        Write-Verbose "Scanning subscription: $subName ($subId)"

        # Get Automation Accounts
        $accounts = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Automation/automationAccounts?api-version=2021-06-22" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $accounts) {
            Write-Verbose "No Automation Accounts found in $subName"
            continue
        }

        Write-Verbose "  Automation Accounts found: $($accounts.Count)"

        foreach ($account in $accounts) {
            $accountName = $account.name

            # Extract Resource Group from ARM ID via regex
            if ($account.id -match '/resourceGroups/([^/]+)/') {
                $rgName = $Matches[1]
            }
            else {
                Write-Warning "Could not extract Resource Group from ID: $($account.id)"
                continue
            }

            Write-Verbose "  Processing account: $accountName ($rgName)"

            # Get Runbooks
            $runbooks = Invoke-AzRARequest `
                -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Automation/automationAccounts/$accountName/runbooks?api-version=2019-06-01" `
                -AccessToken $AccessToken -Method GET -EnablePagination

            if (-not $runbooks) {
                Write-Verbose "    No runbooks in $accountName"
                continue
            }

            Write-Verbose "    Runbooks found: $($runbooks.Count)"

            # Prepare per-account dump directory
            if ($dumpRoot) {
                $safeSubName     = $subName     -replace '[^a-zA-Z0-9_\-]', '_'
                $safeAccountName = $accountName -replace '[^a-zA-Z0-9_\-]', '_'
                $accountDumpDir  = Join-Path (Join-Path $dumpRoot $safeSubName) $safeAccountName
                if (-not (Test-Path $accountDumpDir)) {
                    try {
                        New-Item -ItemType Directory -Force -Path $accountDumpDir -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Warning "Could not create dump directory '$accountDumpDir': $_"
                        $accountDumpDir = $null
                    }
                }
            }

            foreach ($runbook in $runbooks) {
                $runbookName = $runbook.name
                $runbookType = $runbook.properties.runbookType
                $runbookState = $runbook.properties.state

                # Determine file extension from runbook type
                $ext = switch -Wildcard ($runbookType) {
                    'PowerShell*' { 'ps1' }
                    'Python*'     { 'py'  }
                    'Graph*'      { 'ps1' }
                    default       { 'txt' }
                }

                # Download runbook content with retry (only Published runbooks have content)
                $content = $null
                if ($runbookState -eq 'Published') {
                    try {
                        $raw = Invoke-AzWithRetry `
                            -OperationName "Get runbook content: $runbookName" `
                            -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec `
                            -ScriptBlock {
                                Invoke-RestMethod `
                                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Automation/automationAccounts/$accountName/runbooks/$runbookName/content?api-version=2019-06-01" `
                                    -Headers @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' } `
                                    -Method GET `
                                    -ErrorAction Stop
                            }
                        $content = [string]$raw
                    }
                    catch {
                        Write-Warning "    Could not download content for runbook '$runbookName': $_"
                    }
                }
                else {
                    Write-Verbose "    Skipping content download for '$runbookName' (state: $runbookState)"
                }

                # Save to disk
                $filePath = $null
                if ($dumpRoot -and $accountDumpDir -and (Test-Path $accountDumpDir)) {
                    $safeRunbookName = $runbookName -replace '[^a-zA-Z0-9_\-]', '_'
                    $filePath = Join-Path $accountDumpDir "$safeRunbookName.$ext"
                    if ($content) {
                        try {
                            Set-Content -Path $filePath -Value $content -Encoding UTF8 -ErrorAction Stop
                            Write-Verbose "    Saved: $filePath"
                        }
                        catch {
                            Write-Warning "    Could not save runbook '$runbookName' to disk: $_"
                            $filePath = $null
                        }
                    }
                }

                # Scan for secrets
                $secretFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
                if ($ScanSecrets -and $content) {
                    $lines = $content -split "`n"
                    for ($i = 0; $i -lt $lines.Count; $i++) {
                        $line = $lines[$i]
                        foreach ($kw in $Keywords) {
                            if ($line -match "(?i)$kw\s*[=:]\s*[`"']?([^`"'\s]{4,})[`"']?") {
                                $matchedValue = $Matches[1]
                                # Filter PS variables and trivial values
                                if ($matchedValue -notmatch '^\$' -and
                                    $matchedValue -notin @('null','true','false','""',"''",'$null','none','undefined')) {
                                    $finding = [PSCustomObject]@{
                                        Keyword     = $kw
                                        Line        = $i + 1
                                        MatchedLine = $line.Trim()
                                    }
                                    $secretFindings.Add($finding)
                                    $allSecrets.Add([PSCustomObject]@{
                                        SubscriptionName  = $subName
                                        SubscriptionId    = $subId
                                        AutomationAccount = $accountName
                                        ResourceGroup     = $rgName
                                        RunbookName       = $runbookName
                                        RunbookType       = $runbookType
                                        Keyword           = $kw
                                        Line              = $i + 1
                                        MatchedLine       = $line.Trim()
                                    })
                                    Write-Verbose "    [SECRET] '$kw' in $runbookName (line $($i + 1))"
                                }
                            }
                        }
                    }
                }

                $obj = [PSCustomObject]@{
                    SubscriptionId    = $subId
                    SubscriptionName  = $subName
                    AutomationAccount = $accountName
                    ResourceGroup     = $rgName
                    RunbookName       = $runbookName
                    RunbookType       = $runbookType
                    RunbookState      = $runbookState
                    LastModified      = $runbook.properties.lastModifiedTime
                    ContentSizeBytes  = if ($content) { [System.Text.Encoding]::UTF8.GetByteCount([string]$content) } else { 0 }
                    FilePath          = $filePath
                    SecretFindings    = $secretFindings.ToArray()
                    HasSecrets        = ($secretFindings.Count -gt 0)
                }

                $allRunbooks.Add($obj)
            }
        }
    }

    # Export CSV reports
    if ($OutputPath -and $allRunbooks.Count -gt 0) {
        try {
            $csvFile = Join-Path $OutputPath "AzRA-AutomationRunbooks_$timestamp.csv"
            $allRunbooks | Select-Object SubscriptionName, SubscriptionId, AutomationAccount,
                ResourceGroup, RunbookName, RunbookType, RunbookState, LastModified,
                ContentSizeBytes, FilePath, HasSecrets |
                Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Verbose "Runbooks report exported to: $csvFile"
        }
        catch {
            Write-Warning "Could not export runbooks CSV: $_"
        }
    }

    if ($OutputPath -and $ScanSecrets -and $allSecrets.Count -gt 0) {
        try {
            $secretsCsv = Join-Path $OutputPath "AzRA-AutomationRunbooks-Secrets_$timestamp.csv"
            $allSecrets | Export-Csv -Path $secretsCsv -NoTypeInformation -Encoding UTF8
            Write-Verbose "Secrets report exported to: $secretsCsv"
        }
        catch {
            Write-Warning "Could not export secrets CSV: $_"
        }
    }

    return $allRunbooks.ToArray()
}
