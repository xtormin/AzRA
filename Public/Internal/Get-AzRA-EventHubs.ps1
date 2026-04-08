# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin

function Get-AzRA-EventHubs {
    <#
    .SYNOPSIS
    Enumerates Azure Event Hub namespaces and audits security misconfigurations.
    Optionally retrieves SAS keys (Shared Access Signatures) for each authorization rule.

    .DESCRIPTION
    Iterates across all accessible subscriptions, lists all Event Hub namespaces, and
    evaluates each against security checks:

      Critical:     PublicNetworkAccessEnabled (no firewall), SASKeysActive (localAuth not disabled),
                    ManageKeyFound (SAS key with Manage permission = read + write + admin)
      High:         NoFirewallRules, MinimumTlsWeak, DiagnosticLogsDisabled,
                    BasicOrStandardSku (no private endpoints, no VNet)
      Informational: NoPrivateEndpoints, ZoneRedundancyDisabled, AutoInflateEnabled

    With -ScanSecrets, enumerates all authorization rules at namespace level and per Event Hub,
    then calls listKeys for each to retrieve primaryKey, secondaryKey, primaryConnectionString,
    secondaryConnectionString. Rules with Manage permission allow reading, writing, and
    managing the namespace (equivalent to admin access).

    Required permissions:
      Microsoft.EventHub/namespaces/read
      Microsoft.EventHub/namespaces/authorizationRules/listkeys/action   (for -ScanSecrets)
      Microsoft.EventHub/namespaces/eventhubs/authorizationRules/listkeys/action  (for -ScanSecrets)
      microsoft.insights/diagnosticSettings/read  (optional)

    .PARAMETER AccessToken
    Azure Management API access token. Obtain with:
      (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

    .PARAMETER SubscriptionId
    Target a single subscription. If omitted, all accessible subscriptions are scanned.

    .PARAMETER OutputPath
    Folder where output is saved. Raw dumps under:
      <OutputPath>\EventHubsRawDump\<SubscriptionName>\<NamespaceName>\namespace.json
      <OutputPath>\EventHubsRawDump\<SubscriptionName>\<NamespaceName>\authRules.json
    CSV reports:
      <OutputPath>\AzRA-EventHubs_<timestamp>.csv
      <OutputPath>\AzRA-EventHubs-Keys_<timestamp>.csv  (only if -ScanSecrets)

    .PARAMETER ScanSecrets
    If specified, enumerates authorization rules at namespace and Event Hub level and
    retrieves connection strings + keys via listKeys.

    .PARAMETER MaxRetries
    Maximum retry attempts. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries. Default: 5.

    .EXAMPLE
    $token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
    Get-AzRA-EventHubs -AccessToken $token

    .EXAMPLE
    Get-AzRA-EventHubs -AccessToken $token -ScanSecrets -OutputPath 'C:\Audit'

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    One object per Event Hub namespace.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]  [string]$AccessToken,
        [Parameter(Mandatory = $false)] [string]$SubscriptionId,
        [Parameter(Mandatory = $false)] [string]$OutputPath,
        [Parameter(Mandatory = $false)] [switch]$ScanSecrets,
        [Parameter(Mandatory = $false)] [ValidateRange(1,10)]  [int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)] [ValidateRange(1,60)]  [int]$RetryDelaySec = 5
    )

    function Get-RgFromId {
        param([string]$ResourceId)
        if ($ResourceId -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
        return $null
    }

    function Get-ArmHeaders { return @{ 'Authorization' = "Bearer $AccessToken"; 'Content-Type' = 'application/json' } }

    function Invoke-ListKeys {
        param([string]$Uri, [string]$RuleName)
        try { return Invoke-RestMethod -Uri $Uri -Headers (Get-ArmHeaders) -Method POST -ErrorAction Stop }
        catch {
            $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
            if ($code -in @(401,403)) { Write-Warning "    [403] Sin permiso listkeys para: $RuleName" }
            else { Write-Verbose "    listkeys failed ($code): $Uri" }
            return $null
        }
    }

    # -- Init ------------------------------------------------------------------

    $allNamespaces = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allKeys       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $timestamp     = Get-Date -Format 'yyyyMMdd-HHmm'
    $dumpRoot      = $null

    if ($OutputPath) {
        try {
            if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Force -Path $OutputPath -ErrorAction Stop | Out-Null }
            $dumpRoot = Join-Path $OutputPath 'EventHubsRawDump'
            if (-not (Test-Path $dumpRoot)) { New-Item -ItemType Directory -Force -Path $dumpRoot -ErrorAction Stop | Out-Null }
        }
        catch { throw "Cannot create output directory '$OutputPath': $_" }
    }

    Write-Host ""
    Write-Host "[*] Event Hubs - iniciando auditoria..." -ForegroundColor Cyan

    if ($SubscriptionId) {
        $subs = Invoke-AzRARequest -Uri "https://management.azure.com/subscriptions/$SubscriptionId`?api-version=2022-12-01" -AccessToken $AccessToken -Method GET
        if (-not $subs) { throw "Subscription not found: $SubscriptionId" }
        $subs = @($subs)
    }
    else {
        $subs = Invoke-AzRARequest -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' -AccessToken $AccessToken -Method GET -EnablePagination
    }

    Write-Host "  [~] Subscripciones a analizar: $(@($subs).Count)" -ForegroundColor Gray

    foreach ($sub in $subs) {
        $subId   = $sub.subscriptionId
        $subName = $sub.displayName

        Write-Host ""
        Write-Host "  [*] Subscripcion: $subName ($subId)" -ForegroundColor Cyan
        Write-Host "    [~] Enumerando Event Hub namespaces..." -ForegroundColor Gray

        $namespaces = Invoke-AzRARequest `
            -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.EventHub/namespaces?api-version=2024-01-01" `
            -AccessToken $AccessToken -Method GET -EnablePagination

        if (-not $namespaces) { Write-Host "    [~] Sin Event Hub namespaces en esta subscripcion" -ForegroundColor Gray; continue }
        Write-Host "    [+] Namespaces encontrados: $(@($namespaces).Count)" -ForegroundColor White

        foreach ($ns in $namespaces) {
            $nsName  = $ns.name
            $rgName  = Get-RgFromId -ResourceId $ns.id
            $props   = $ns.properties
            $sku     = $ns.sku.name

            Write-Host "    [~] Analizando: $nsName [SKU: $sku]" -ForegroundColor Gray

            # -- Security checks -----------------------------------------------

            $pubNetEnabled   = ($props.publicNetworkAccess -ne 'Disabled')
            $ipRules         = @($props.networkRuleSets.ipRules)
            $vnetRules       = @($props.networkRuleSets.virtualNetworkRules)

            # Get network rule set detail (may be sub-resource)
            $netRuleSet = $null
            try {
                $netRuleSet = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.EventHub/namespaces/$nsName/networkRuleSets/default?api-version=2024-01-01" `
                    -AccessToken $AccessToken -Method GET -ErrorAction Stop
            }
            catch {}

            if ($netRuleSet) {
                $ipRules    = @($netRuleSet.properties.ipRules)
                $vnetRules  = @($netRuleSet.properties.virtualNetworkRules)
                $defaultAction = $netRuleSet.properties.defaultAction
            }
            else {
                $defaultAction = 'Allow'
            }

            $noFirewallRules   = ($pubNetEnabled -and $defaultAction -eq 'Allow' -and $ipRules.Count -eq 0 -and $vnetRules.Count -eq 0)
            $privateEps        = @($props.privateEndpointConnections)
            $noPrivateEp       = ($privateEps.Count -eq 0)
            $localAuthDisabled = ($props.disableLocalAuth -eq $true)
            $minTlsWeak        = ($props.minimumTlsVersion -in @('1.0', '1.1'))
            $basicOrStdSku     = ($sku -in @('Basic', 'Standard'))
            $zoneRedundant     = ($props.zoneRedundant -eq $true)

            # Diagnostic settings
            $diagLogsDisabled = $null
            try {
                $diag = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/$($ns.id)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview" `
                    -AccessToken $AccessToken -Method GET -ErrorAction Stop
                $diagLogsDisabled = ($null -eq $diag -or @($diag).Count -eq 0)
            }
            catch { Write-Verbose "    Sin acceso a diagnostic settings para $nsName" }

            # -- SAS key extraction --------------------------------------------

            $keys            = [System.Collections.Generic.List[PSCustomObject]]::new()
            $hasKeys         = $false
            $manageKeyFound  = $false
            $authRulesRaw    = $null

            if ($ScanSecrets) {
                Write-Host "      [~] Enumerando authorization rules..." -ForegroundColor Gray

                # Namespace-level auth rules
                $authRules = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.EventHub/namespaces/$nsName/authorizationRules?api-version=2024-01-01" `
                    -AccessToken $AccessToken -Method GET -EnablePagination
                $authRulesRaw = $authRules

                if ($authRules) {
                    foreach ($rule in $authRules) {
                        $ruleName = $rule.name
                        $rights   = @($rule.properties.rights)
                        $isManage = ($rights -contains 'Manage')

                        $listUri  = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.EventHub/namespaces/$nsName/authorizationRules/$ruleName/listkeys?api-version=2024-01-01"
                        $keysResp = Invoke-ListKeys -Uri $listUri -RuleName "$nsName/$ruleName"

                        if ($keysResp) {
                            if ($isManage) { $manageKeyFound = $true }
                            foreach ($pair in @(
                                @{ KeyType = 'primaryKey';               Value = $keysResp.primaryKey },
                                @{ KeyType = 'secondaryKey';             Value = $keysResp.secondaryKey },
                                @{ KeyType = 'primaryConnectionString';  Value = $keysResp.primaryConnectionString },
                                @{ KeyType = 'secondaryConnectionString';Value = $keysResp.secondaryConnectionString }
                            )) {
                                if ($pair.Value) {
                                    $entry = [PSCustomObject]@{
                                        SubscriptionName = $subName
                                        SubscriptionId   = $subId
                                        ResourceGroup    = $rgName
                                        NamespaceName    = $nsName
                                        Scope            = 'Namespace'
                                        RuleName         = $ruleName
                                        Rights           = ($rights -join ', ')
                                        IsManage         = $isManage
                                        KeyType          = $pair.KeyType
                                        Value            = $pair.Value
                                    }
                                    $keys.Add($entry)
                                    $allKeys.Add($entry)
                                }
                            }
                        }
                    }
                }

                # Per Event Hub auth rules
                $eventHubs = Invoke-AzRARequest `
                    -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.EventHub/namespaces/$nsName/eventhubs?api-version=2024-01-01" `
                    -AccessToken $AccessToken -Method GET -EnablePagination

                if ($eventHubs) {
                    foreach ($eh in $eventHubs) {
                        $ehName  = $eh.name
                        $ehRules = Invoke-AzRARequest `
                            -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.EventHub/namespaces/$nsName/eventhubs/$ehName/authorizationRules?api-version=2024-01-01" `
                            -AccessToken $AccessToken -Method GET -EnablePagination

                        if ($ehRules) {
                            foreach ($rule in $ehRules) {
                                $ruleName = $rule.name
                                $rights   = @($rule.properties.rights)
                                $isManage = ($rights -contains 'Manage')
                                $listUri  = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.EventHub/namespaces/$nsName/eventhubs/$ehName/authorizationRules/$ruleName/listkeys?api-version=2024-01-01"
                                $keysResp = Invoke-ListKeys -Uri $listUri -RuleName "$nsName/$ehName/$ruleName"

                                if ($keysResp) {
                                    if ($isManage) { $manageKeyFound = $true }
                                    foreach ($pair in @(
                                        @{ KeyType = 'primaryKey';               Value = $keysResp.primaryKey },
                                        @{ KeyType = 'primaryConnectionString';  Value = $keysResp.primaryConnectionString }
                                    )) {
                                        if ($pair.Value) {
                                            $entry = [PSCustomObject]@{
                                                SubscriptionName = $subName
                                                SubscriptionId   = $subId
                                                ResourceGroup    = $rgName
                                                NamespaceName    = $nsName
                                                Scope            = "EventHub:$ehName"
                                                RuleName         = $ruleName
                                                Rights           = ($rights -join ', ')
                                                IsManage         = $isManage
                                                KeyType          = $pair.KeyType
                                                Value            = $pair.Value
                                            }
                                            $keys.Add($entry)
                                            $allKeys.Add($entry)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                $hasKeys = ($keys.Count -gt 0)
                if ($hasKeys) { Write-Host "      [+] SAS keys extraidas: $($keys.Count) (Manage: $manageKeyFound)" -ForegroundColor $(if ($manageKeyFound) { 'Red' } else { 'White' }) }
            }

            # -- Summary flags -------------------------------------------------

            $hasCritical = ($noFirewallRules -or ($hasKeys -and $manageKeyFound))
            $hasHigh     = ($minTlsWeak -or $basicOrStdSku -or (-not $localAuthDisabled -and -not $hasCritical) -or ($diagLogsDisabled -eq $true))

            if ($hasCritical) {
                Write-Host "    [!] CRITICO: $nsName" -ForegroundColor Red
                if ($noFirewallRules)                { Write-Host "        - NoFirewallRules: acceso publico sin restricciones IP ni VNet" -ForegroundColor Red }
                if ($hasKeys -and $manageKeyFound)   { Write-Host "        - ManageKeyFound: SAS key con permiso Manage encontrada (lectura + escritura + admin)" -ForegroundColor Red }
            }
            elseif ($hasHigh) {
                Write-Host "    [!] ALTO: $nsName" -ForegroundColor Yellow
                if ($minTlsWeak)                        { Write-Host "        - MinTlsWeak: TLS minimo debil ($($props.minimumTlsVersion))" -ForegroundColor Yellow }
                if ($basicOrStdSku)                     { Write-Host "        - BasicOrStandardSku: SKU $sku sin soporte para private endpoints ni VNet rules completas" -ForegroundColor Yellow }
                if (-not $localAuthDisabled)            { Write-Host "        - LocalAuthEnabled: SAS keys activas (disableLocalAuth=false)" -ForegroundColor Yellow }
                if ($diagLogsDisabled -eq $true)        { Write-Host "        - DiagnosticLogsDisabled: sin Diagnostic Settings" -ForegroundColor Yellow }
            }
            else { Write-Host "    [OK] $nsName" -ForegroundColor Green }

            # -- Raw dump ------------------------------------------------------

            $rawFilePath = $null
            if ($dumpRoot -and $rgName) {
                $dir = Join-Path (Join-Path $dumpRoot ($subName -replace '[^a-zA-Z0-9_\-]','_')) ($nsName -replace '[^a-zA-Z0-9_\-]','_')
                if (-not (Test-Path $dir)) { try { New-Item -ItemType Directory -Force -Path $dir -ErrorAction Stop | Out-Null } catch {} }
                if (Test-Path $dir) {
                    try { $ns | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $dir 'namespace.json') -Encoding UTF8 -ErrorAction Stop } catch {}
                    if ($authRulesRaw) { try { $authRulesRaw | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $dir 'authRules.json') -Encoding UTF8 -ErrorAction Stop } catch {} }
                    $rawFilePath = $dir
                }
            }

            $allNamespaces.Add([PSCustomObject]@{
                SubscriptionId        = $subId
                SubscriptionName      = $subName
                ResourceGroup         = $rgName
                NamespaceName         = $nsName
                Sku                   = $sku
                Location              = $ns.location
                ServiceBusEndpoint    = $props.serviceBusEndpoint
                PublicNetworkEnabled  = $pubNetEnabled
                NoFirewallRules       = $noFirewallRules
                NoPrivateEndpoint     = $noPrivateEp
                LocalAuthEnabled      = (-not $localAuthDisabled)
                MinTlsWeak            = $minTlsWeak
                BasicOrStandardSku    = $basicOrStdSku
                ZoneRedundant         = $zoneRedundant
                DiagnosticLogsDisabled = $diagLogsDisabled
                HasKeys               = $hasKeys
                ManageKeyFound        = $manageKeyFound
                KeyCount              = $keys.Count
                Keys                  = $keys.ToArray()
                HasCriticalFindings   = $hasCritical
                HasHighFindings       = $hasHigh
                RawFilePath           = $rawFilePath
            })
        }
    }

    if ($OutputPath -and $allNamespaces.Count -gt 0) {
        try {
            $allNamespaces.ToArray() | Select-Object SubscriptionName, ResourceGroup, NamespaceName, Sku,
                Location, PublicNetworkEnabled, NoFirewallRules, NoPrivateEndpoint,
                LocalAuthEnabled, MinTlsWeak, BasicOrStandardSku, ZoneRedundant,
                DiagnosticLogsDisabled, HasKeys, ManageKeyFound, KeyCount,
                HasCriticalFindings, HasHighFindings, RawFilePath |
                Export-Csv -Path (Join-Path $OutputPath "AzRA-EventHubs_$timestamp.csv") -NoTypeInformation -Encoding UTF8
        } catch { Write-Warning "Could not export EventHubs CSV: $_" }

        if ($ScanSecrets -and $allKeys.Count -gt 0) {
            try {
                $allKeys.ToArray() | Select-Object SubscriptionName, ResourceGroup, NamespaceName,
                    Scope, RuleName, Rights, IsManage, KeyType, Value |
                    Export-Csv -Path (Join-Path $OutputPath "AzRA-EventHubs-Keys_$timestamp.csv") -NoTypeInformation -Encoding UTF8
            } catch { Write-Warning "Could not export keys CSV: $_" }
        }
    }

    $critCount  = ($allNamespaces | Where-Object { $_.HasCriticalFindings }).Count
    $highCount  = ($allNamespaces | Where-Object { $_.HasHighFindings -and -not $_.HasCriticalFindings }).Count
    $totalCount = $allNamespaces.Count

    Write-Host ""
    Write-Host "[*] Auditoria completada: $totalCount Event Hub namespaces analizados" -ForegroundColor Cyan
    if ($critCount -gt 0) { Write-Host "  [!] Namespaces con hallazgos CRITICOS: $critCount" -ForegroundColor Red }
    if ($highCount -gt 0) { Write-Host "  [!] Namespaces con hallazgos ALTOS: $highCount" -ForegroundColor Yellow }
    if ($ScanSecrets) {
        $nsWithKeys = ($allNamespaces | Where-Object { $_.HasKeys }).Count
        Write-Host "  [+] SAS keys extraidas de $nsWithKeys namespaces ($($allKeys.Count) keys total)" -ForegroundColor White
        $manageCount = ($allNamespaces | Where-Object { $_.ManageKeyFound }).Count
        if ($manageCount -gt 0) { Write-Host "  [!] Namespaces con Manage key: $manageCount" -ForegroundColor Red }
    }
    if ($OutputPath) { Write-Host "  [+] Resultados exportados en: $OutputPath" -ForegroundColor White }
    Write-Host ""

    return $allNamespaces.ToArray()
}
