# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-LogicApps {
    <#
    .SYNOPSIS
    Enumerates Azure Logic Apps and optionally scans their definitions for exposed secrets and attack surface.

    .DESCRIPTION
    Iterates across all accessible subscriptions (or a specific one), retrieves the full definition
    of every Logic App, and analyzes workflow parameters, HTTP actions, triggers, and tags for
    hardcoded credentials or sensitive information.

    When -OutputPath is specified, saves the raw JSON definition of each Logic App to disk and
    exports findings to CSV reports. When -IncludeVersions is specified, also retrieves and
    analyzes the version history of each Logic App.

    Returns one PSCustomObject per Logic App to the pipeline.

    Required permissions:
      Microsoft.Logic/workflows/read

    .PARAMETER AccessToken
    Azure Management API access token (JWT). Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription by ID. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where all output is saved. Raw JSON definitions are saved under:
      <OutputPath>\LogicAppsRawDump\<SubscriptionName>\<ResourceGroupName>\<LogicAppName>.json
    Version history (if -IncludeVersions) is saved as:
      <OutputPath>\LogicAppsRawDump\<SubscriptionName>\<ResourceGroupName>\<LogicAppName>_versions.json
    CSV reports are saved as:
      <OutputPath>\AzRA-LogicApps_<yyyyMMdd-HHmm>.csv
      <OutputPath>\AzRA-LogicApps-Secrets_<yyyyMMdd-HHmm>.csv  (only if -ScanSecrets)

    .PARAMETER ScanSecrets
    If specified, scans each Logic App definition for sensitive strings across four sources:
      - Workflow parameters (properties.parameters) — by name keyword and type SecureString
      - HTTP actions (properties.definition.actions) — URIs, headers, body, authentication
      - Triggers (properties.definition.triggers) — exposed Request triggers and inputs
      - Tags — key/value pairs matching keywords
    Findings are included in the pipeline objects and exported to a separate CSV when -OutputPath is set.

    .PARAMETER IncludeVersions
    If specified, retrieves the version history of each Logic App via the versions API.
    Version data is dumped to disk when -OutputPath is set, and scanned for secrets when
    -ScanSecrets is also active. This adds one API call per Logic App.

    .PARAMETER Keywords
    Keywords used to detect sensitive assignments in workflow parameters, action inputs, and tags.
    Defaults to a broad list including credential, connection, and API key related terms.

    .PARAMETER MaxRetries
    Maximum retry attempts on throttling (HTTP 429) or transient errors (5xx).
    Must be between 1 and 10. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries (multiplied by attempt number).
    Must be between 1 and 60. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-LogicApps -AccessToken $token
    Enumerates all Logic Apps across all subscriptions and returns metadata to the pipeline.

    .EXAMPLE
    Get-AzRA-LogicApps -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Scans a single subscription.

    .EXAMPLE
    Get-AzRA-LogicApps -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets
    Full audit: dumps raw definitions and exports findings CSVs.

    .EXAMPLE
    Get-AzRA-LogicApps -AccessToken $token -ScanSecrets |
        Where-Object { $_.HasSecrets } |
        Select-Object LogicAppName, ResourceGroup, SecretFindings
    Returns only Logic Apps with findings.

    .EXAMPLE
    Get-AzRA-LogicApps -AccessToken $token |
        Where-Object { $_.HasExposedTrigger } |
        Select-Object LogicAppName, ResourceGroup, TriggerTypes
    Returns Logic Apps with Request triggers exposed to the internet.

    .EXAMPLE
    Get-AzRA-LogicApps -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets -IncludeVersions
    Full audit including version history analysis.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Each object contains: SubscriptionId, SubscriptionName, ResourceGroup, LogicAppName,
    Location, State, CreatedTime, ChangedTime, TriggerCount, TriggerTypes, HasExposedTrigger,
    ExposedEndpoints, ActionCount, HttpActionCount, HasHttpActions, WorkflowParameterCount,
    SecureStringParamCount, PlaintextParamCount, Tags, VersionCount, SecretFindings,
    HasSecrets, RawFilePath.

    .LINK
    https://learn.microsoft.com/en-us/rest/api/logic/workflows
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
        [switch]$IncludeVersions,

        [Parameter(Mandatory = $false)]
        [string[]]$Keywords = @(
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'credential', 'cred', 'apikey', 'api_key', 'connectionstring',
            'connstr', 'sas', 'auth', 'access_key', 'client_secret',
            'authorization', 'bearer', 'subscription_key', 'ocp-apim'
        ),

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySec = 5
    )

    # ── Helpers ───────────────────────────────────────────────────────────────

    function Get-RgFromId {
        param([string]$ResourceId)
        if ($ResourceId -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
        return $null
    }

    function Get-LogicAppApiHeaders {
        return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    }

    # Iterates an action tree using a queue (avoids stack overflow on deep definitions)
    function Get-AllActions {
        param($ActionsObject)
        $result = [System.Collections.Generic.List[object]]::new()
        if (-not $ActionsObject) { return $result }

        $queue = [System.Collections.Generic.Queue[object]]::new()
        foreach ($prop in $ActionsObject.PSObject.Properties) { $queue.Enqueue($prop.Value) }

        while ($queue.Count -gt 0) {
            $action = $queue.Dequeue()
            $result.Add($action)
            # Enqueue nested actions
            foreach ($subProp in @('actions','else')) {
                $sub = $action.$subProp
                if ($sub -and $sub.PSObject.Properties) {
                    foreach ($p in $sub.PSObject.Properties) { $queue.Enqueue($p.Value) }
                }
            }
            # If/Switch branches
            if ($action.cases -and $action.cases.PSObject.Properties) {
                foreach ($case in $action.cases.PSObject.Properties) {
                    if ($case.Value.actions -and $case.Value.actions.PSObject.Properties) {
                        foreach ($p in $case.Value.actions.PSObject.Properties) { $queue.Enqueue($p.Value) }
                    }
                }
            }
        }
        return $result
    }

    function Test-SensitiveString {
        param([string]$Value, [string[]]$Keywords)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        $falsePositives = @(
            'null','true','false','undefined','none','n/a','',
            'application/json','text/plain','text/html',
            '@{body}','@{outputs}','@{triggerBody}'
        )
        if ($falsePositives -contains $Value.ToLower()) { return $false }
        # Skip Logic Apps dynamic expressions (@{...})
        if ($Value -match '^\s*@\{') { return $false }
        foreach ($kw in $Keywords) {
            if ($Value -match "(?i)$kw") { return $true }
        }
        return $false
    }

    function Invoke-ScanLogicAppSecrets {
        param(
            [string]$SubName, [string]$SubId, [string]$RgName, [string]$LaName,
            $WfParams, $Definition, $Tags, [string[]]$Keywords,
            [string]$VersionId = $null
        )

        $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

        function Add-Finding {
            param([string]$Source, [string]$SubSource, [string]$FindingType,
                  [string]$Keyword, [string]$PropertyPath, [string]$MatchedValue)
            $truncated = if ($MatchedValue.Length -gt 200) { $MatchedValue.Substring(0,200) + '...' } else { $MatchedValue }
            $findings.Add([PSCustomObject]@{
                Source       = $Source
                SubSource    = $SubSource
                FindingType  = $FindingType
                Keyword      = $Keyword
                PropertyPath = $PropertyPath
                MatchedValue = $truncated
                VersionId    = $VersionId
            })
        }

        # ── Source A: Workflow parameters ────────────────────────────────────
        if ($WfParams -and $WfParams.PSObject.Properties) {
            foreach ($param in $WfParams.PSObject.Properties) {
                $pName  = $param.Name
                $pType  = $param.Value.type
                $pValue = $param.Value.value

                # SecureString params: always report (existence is already sensitive)
                if ($pType -eq 'SecureString') {
                    Add-Finding -Source 'WorkflowParam' -SubSource $pName `
                        -FindingType 'SecureString' -Keyword 'SecureString' `
                        -PropertyPath "properties.parameters.$pName.type" `
                        -MatchedValue "[SecureString parameter]"
                    continue
                }

                # Keyword match on param name
                $kwMatch = $Keywords | Where-Object { $pName -match "(?i)$_" } | Select-Object -First 1
                if ($kwMatch) {
                    $valueStr = if ($pValue) { ($pValue | ConvertTo-Json -Compress -Depth 3) } else { '' }
                    if ($valueStr -and $valueStr.Length -gt 2 -and $valueStr -notmatch '^\s*@\{') {
                        Add-Finding -Source 'WorkflowParam' -SubSource $pName `
                            -FindingType 'PlainText' -Keyword $kwMatch `
                            -PropertyPath "properties.parameters.$pName.value" `
                            -MatchedValue $valueStr
                    }
                }
            }
        }

        # ── Source B: HTTP actions (recursive tree walk) ──────────────────────
        if ($Definition -and $Definition.actions) {
            $allActions = Get-AllActions -ActionsObject $Definition.actions
            foreach ($action in $allActions) {
                if (-not $action.type) { continue }

                if ($action.type -eq 'Http' -and $action.inputs) {
                    $inputs = $action.inputs

                    # URI
                    if ($inputs.uri -and (Test-SensitiveString -Value ([string]$inputs.uri) -Keywords $Keywords)) {
                        Add-Finding -Source 'HttpAction' -SubSource $action.type `
                            -FindingType 'HttpUri' -Keyword 'uri' `
                            -PropertyPath 'inputs.uri' -MatchedValue ([string]$inputs.uri)
                    }

                    # Headers
                    if ($inputs.headers -and $inputs.headers.PSObject.Properties) {
                        foreach ($hdr in $inputs.headers.PSObject.Properties) {
                            $kwMatch = $Keywords | Where-Object { $hdr.Name -match "(?i)$_" } | Select-Object -First 1
                            if ($kwMatch) {
                                Add-Finding -Source 'HttpAction' -SubSource $hdr.Name `
                                    -FindingType 'HttpHeader' -Keyword $kwMatch `
                                    -PropertyPath "inputs.headers.$($hdr.Name)" `
                                    -MatchedValue ([string]$hdr.Value)
                            }
                        }
                    }

                    # Authentication block
                    if ($inputs.authentication) {
                        $authJson = $inputs.authentication | ConvertTo-Json -Compress -Depth 5
                        Add-Finding -Source 'HttpAction' -SubSource 'authentication' `
                            -FindingType 'HttpAuth' -Keyword 'authentication' `
                            -PropertyPath 'inputs.authentication' -MatchedValue $authJson
                    }

                    # Body (scan for keywords)
                    if ($inputs.body) {
                        $bodyStr = $inputs.body | ConvertTo-Json -Compress -Depth 5
                        $kwMatch = $Keywords | Where-Object { $bodyStr -match "(?i)$_" } | Select-Object -First 1
                        if ($kwMatch) {
                            Add-Finding -Source 'HttpAction' -SubSource 'body' `
                                -FindingType 'HttpBody' -Keyword $kwMatch `
                                -PropertyPath 'inputs.body' -MatchedValue $bodyStr
                        }
                    }
                }
                else {
                    # Generic scan of inputs for any action type
                    if ($action.inputs) {
                        $inputsStr = $action.inputs | ConvertTo-Json -Compress -Depth 5
                        $kwMatch = $Keywords | Where-Object { $inputsStr -match "(?i)$_" } | Select-Object -First 1
                        if ($kwMatch -and ($inputsStr -notmatch '^\s*@\{')) {
                            Add-Finding -Source 'Action' -SubSource $action.type `
                                -FindingType 'ActionInput' -Keyword $kwMatch `
                                -PropertyPath 'inputs' -MatchedValue $inputsStr
                        }
                    }
                }
            }
        }

        # ── Source C: Triggers ────────────────────────────────────────────────
        if ($Definition -and $Definition.triggers -and $Definition.triggers.PSObject.Properties) {
            foreach ($trig in $Definition.triggers.PSObject.Properties) {
                $trigType = $trig.Value.type

                if ($trigType -eq 'ApiConnection' -and $trig.Value.inputs) {
                    $trigInputsStr = $trig.Value.inputs | ConvertTo-Json -Compress -Depth 5
                    $kwMatch = $Keywords | Where-Object { $trigInputsStr -match "(?i)$_" } | Select-Object -First 1
                    if ($kwMatch) {
                        Add-Finding -Source 'Trigger' -SubSource $trig.Name `
                            -FindingType 'TriggerInput' -Keyword $kwMatch `
                            -PropertyPath "triggers.$($trig.Name).inputs" `
                            -MatchedValue $trigInputsStr
                    }
                }
            }
        }

        # ── Source D: Tags ────────────────────────────────────────────────────
        if ($Tags -and $Tags.PSObject.Properties) {
            foreach ($tag in $Tags.PSObject.Properties) {
                $combined = "$($tag.Name) $($tag.Value)"
                $kwMatch = $Keywords | Where-Object { $combined -match "(?i)$_" } | Select-Object -First 1
                if ($kwMatch) {
                    Add-Finding -Source 'Tag' -SubSource $tag.Name `
                        -FindingType 'TagValue' -Keyword $kwMatch `
                        -PropertyPath "tags.$($tag.Name)" -MatchedValue ([string]$tag.Value)
                }
            }
        }

        return $findings
    }

    # ── Initialization ────────────────────────────────────────────────────────

    $allLogicApps = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSecrets   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp    = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot     = $null

    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null
            }
            $dumpRoot = Join-Path $OutputPath 'LogicAppsRawDump'
            if (-not (Test-Path $dumpRoot)) {
                New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null
            }
        }
        catch {
            throw "Cannot create output directory '$OutputPath': $_"
        }
    }

    # ── Resolve subscriptions ─────────────────────────────────────────────────

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

    # ── Main loop ─────────────────────────────────────────────────────────────

    foreach ($sub in $subs) {
        $subId   = $sub.subscriptionId
        $subName = $sub.displayName
        Write-Verbose "Scanning subscription: $subName ($subId)"

        # List all Logic Apps in subscription (ARM nextLink pagination)
        $workflows = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Logic/workflows?api-version=2016-06-01" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $workflows) {
            Write-Verbose "  No Logic Apps found in $subName"
            continue
        }

        Write-Verbose "  Logic Apps found: $($workflows.Count)"

        foreach ($wf in $workflows) {
            $laName = $wf.name
            $rgName = Get-RgFromId -ResourceId $wf.id

            if (-not $rgName) {
                Write-Warning "  Could not extract Resource Group for Logic App '$laName'"
                continue
            }

            Write-Verbose "  Processing: $laName ($rgName)"

            # Fetch full definition (list endpoint may truncate large definitions)
            $fullDetail = $null
            try {
                $fullDetail = Invoke-AzWithRetry `
                    -OperationName "Get Logic App detail: $laName" `
                    -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec `
                    -ScriptBlock {
                        Invoke-RestMethod `
                            -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Logic/workflows/$laName`?api-version=2016-06-01" `
                            -Headers (Get-LogicAppApiHeaders) `
                            -Method GET -ErrorAction Stop
                    }
            }
            catch {
                Write-Warning "  Could not fetch definition for '$laName': $_"
                continue
            }

            $props      = $fullDetail.properties
            $definition = $props.definition
            $wfParams   = $props.parameters
            $tags       = $fullDetail.tags

            # ── Extract trigger metadata ───────────────────────────────────
            $triggerTypes     = @()
            $hasExposedTrigger = $false
            $triggerCount     = 0

            if ($definition -and $definition.triggers -and $definition.triggers.PSObject.Properties) {
                $triggerCount = @($definition.triggers.PSObject.Properties).Count
                $triggerTypes = @($definition.triggers.PSObject.Properties | ForEach-Object { $_.Value.type }) | Select-Object -Unique
                $hasExposedTrigger = $triggerTypes -contains 'Request'
            }

            # ── Extract endpoint IPs ───────────────────────────────────────
            $exposedEndpoints = @()
            if ($props.endpointsConfiguration -and
                $props.endpointsConfiguration.workflow -and
                $props.endpointsConfiguration.workflow.accessEndpointIpAddresses) {
                $exposedEndpoints = @($props.endpointsConfiguration.workflow.accessEndpointIpAddresses |
                    ForEach-Object { $_.address })
            }

            # ── Extract action metadata ────────────────────────────────────
            $allActions    = @()
            $httpActionCount = 0
            $actionCount   = 0

            if ($definition -and $definition.actions) {
                $allActions    = @(Get-AllActions -ActionsObject $definition.actions)
                $actionCount   = $allActions.Count
                $httpActionCount = @($allActions | Where-Object { $_.type -eq 'Http' }).Count
            }

            # ── Extract parameter metadata ─────────────────────────────────
            $wfParamCount      = 0
            $secureParamCount  = 0
            $plaintextParamCount = 0

            if ($wfParams -and $wfParams.PSObject.Properties) {
                $wfParamCount = @($wfParams.PSObject.Properties).Count
                $secureParamCount = @($wfParams.PSObject.Properties |
                    Where-Object { $_.Value.type -eq 'SecureString' }).Count
                $plaintextParamCount = $wfParamCount - $secureParamCount
            }

            # ── Raw dump ──────────────────────────────────────────────────
            $rawFilePath = $null
            if ($dumpRoot) {
                $safeSubName = $subName -replace '[^a-zA-Z0-9_\-]', '_'
                $safeRgName  = $rgName  -replace '[^a-zA-Z0-9_\-]', '_'
                $safeLaName  = $laName  -replace '[^a-zA-Z0-9_\-]', '_'
                $rgDumpDir   = Join-Path (Join-Path $dumpRoot $safeSubName) $safeRgName

                if (-not (Test-Path $rgDumpDir)) {
                    try {
                        New-Item -ItemType Directory -Force -Path $rgDumpDir -ErrorAction Stop | Out-Null
                    }
                    catch {
                        Write-Warning "  Could not create dump directory '$rgDumpDir': $_"
                    }
                }

                if (Test-Path $rgDumpDir) {
                    $rawFilePath = Join-Path $rgDumpDir "$safeLaName.json"
                    try {
                        $fullDetail | ConvertTo-Json -Depth 20 |
                            Set-Content -Path $rawFilePath -Encoding UTF8 -ErrorAction Stop
                        Write-Verbose "  Dumped: $rawFilePath"
                    }
                    catch {
                        Write-Warning "  Could not write dump file '$rawFilePath': $_"
                        $rawFilePath = $null
                    }
                }
            }

            # ── Version history ───────────────────────────────────────────
            $versionCount = -1
            $versionItems = @()

            if ($IncludeVersions) {
                try {
                    $versResponse = Invoke-AzWithRetry `
                        -OperationName "Get versions: $laName" `
                        -MaxRetries $MaxRetries -RetryDelaySec $RetryDelaySec `
                        -ScriptBlock {
                            Invoke-RestMethod `
                                -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Logic/workflows/$laName/versions?api-version=2016-06-01" `
                                -Headers (Get-LogicAppApiHeaders) `
                                -Method GET -ErrorAction Stop
                        }
                    $versionItems = if ($versResponse.value) { @($versResponse.value) } else { @() }
                    $versionCount = $versionItems.Count

                    if ($dumpRoot -and $versionItems.Count -gt 0 -and (Test-Path $rgDumpDir)) {
                        $versFile = Join-Path $rgDumpDir "$safeLaName`_versions.json"
                        try {
                            $versionItems | ConvertTo-Json -Depth 20 |
                                Set-Content -Path $versFile -Encoding UTF8 -ErrorAction Stop
                            Write-Verbose "  Dumped versions: $versFile"
                        }
                        catch {
                            Write-Warning "  Could not write versions dump '$versFile': $_"
                        }
                    }
                }
                catch {
                    Write-Warning "  Could not retrieve versions for '$laName': $_"
                    $versionCount = -1
                }
            }

            # ── Scan for secrets ──────────────────────────────────────────
            $secretFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

            if ($ScanSecrets) {
                $findings = Invoke-ScanLogicAppSecrets `
                    -SubName $subName -SubId $subId -RgName $rgName -LaName $laName `
                    -WfParams $wfParams -Definition $definition -Tags $tags `
                    -Keywords $Keywords -VersionId $null

                foreach ($f in $findings) {
                    $secretFindings.Add($f)
                    $allSecrets.Add([PSCustomObject]@{
                        SubscriptionName = $subName
                        SubscriptionId   = $subId
                        ResourceGroup    = $rgName
                        LogicAppName     = $laName
                        Source           = $f.Source
                        SubSource        = $f.SubSource
                        FindingType      = $f.FindingType
                        Keyword          = $f.Keyword
                        PropertyPath     = $f.PropertyPath
                        MatchedValue     = $f.MatchedValue
                        VersionId        = $f.VersionId
                    })
                }

                # Scan versions if available
                if ($IncludeVersions -and $versionItems.Count -gt 0) {
                    foreach ($ver in $versionItems) {
                        $verFindings = Invoke-ScanLogicAppSecrets `
                            -SubName $subName -SubId $subId -RgName $rgName -LaName $laName `
                            -WfParams $ver.properties.parameters `
                            -Definition $ver.properties.definition `
                            -Tags $null -Keywords $Keywords -VersionId $ver.name

                        foreach ($f in $verFindings) {
                            $secretFindings.Add($f)
                            $allSecrets.Add([PSCustomObject]@{
                                SubscriptionName = $subName
                                SubscriptionId   = $subId
                                ResourceGroup    = $rgName
                                LogicAppName     = $laName
                                Source           = $f.Source
                                SubSource        = $f.SubSource
                                FindingType      = $f.FindingType
                                Keyword          = $f.Keyword
                                PropertyPath     = $f.PropertyPath
                                MatchedValue     = $f.MatchedValue
                                VersionId        = $f.VersionId
                            })
                        }
                    }
                }

                if ($secretFindings.Count -gt 0) {
                    Write-Verbose "  [!] $($secretFindings.Count) finding(s) in $laName"
                }
            }

            # ── Build pipeline object ─────────────────────────────────────
            $obj = [PSCustomObject]@{
                SubscriptionId         = $subId
                SubscriptionName       = $subName
                ResourceGroup          = $rgName
                LogicAppName           = $laName
                Location               = $fullDetail.location
                State                  = $props.state
                CreatedTime            = $props.createdTime
                ChangedTime            = $props.changedTime
                TriggerCount           = $triggerCount
                TriggerTypes           = $triggerTypes -join ', '
                HasExposedTrigger      = $hasExposedTrigger
                ExposedEndpoints       = $exposedEndpoints -join ', '
                ActionCount            = $actionCount
                HttpActionCount        = $httpActionCount
                HasHttpActions         = ($httpActionCount -gt 0)
                WorkflowParameterCount = $wfParamCount
                SecureStringParamCount = $secureParamCount
                PlaintextParamCount    = $plaintextParamCount
                Tags                   = $tags
                VersionCount           = $versionCount
                SecretFindings         = $secretFindings.ToArray()
                HasSecrets             = ($secretFindings.Count -gt 0)
                RawFilePath            = $rawFilePath
            }

            $allLogicApps.Add($obj)
        }
    }

    # ── Export CSV reports ────────────────────────────────────────────────────

    if ($OutputPath -and $allLogicApps.Count -gt 0) {
        try {
            $csvFile = Join-Path $OutputPath "AzRA-LogicApps_$timestamp.csv"
            $allLogicApps | Select-Object SubscriptionName, SubscriptionId, ResourceGroup,
                LogicAppName, Location, State, CreatedTime, ChangedTime,
                TriggerCount, TriggerTypes, HasExposedTrigger, ExposedEndpoints,
                ActionCount, HttpActionCount, HasHttpActions,
                WorkflowParameterCount, SecureStringParamCount, PlaintextParamCount,
                VersionCount, HasSecrets, RawFilePath |
                Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Verbose "Logic Apps report exported to: $csvFile"
        }
        catch {
            Write-Warning "Could not export Logic Apps CSV: $_"
        }
    }

    if ($OutputPath -and $ScanSecrets -and $allSecrets.Count -gt 0) {
        try {
            $secretsCsv = Join-Path $OutputPath "AzRA-LogicApps-Secrets_$timestamp.csv"
            $allSecrets | Export-Csv -Path $secretsCsv -NoTypeInformation -Encoding UTF8
            Write-Verbose "Secrets report exported to: $secretsCsv"
        }
        catch {
            Write-Warning "Could not export secrets CSV: $_"
        }
    }

    return $allLogicApps.ToArray()
}
