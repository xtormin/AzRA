# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin
# Description: Internal helper for Az module calls with automatic retry on throttling and transient errors.

function Invoke-AzWithRetry {
    <#
    .SYNOPSIS
    Executes an Az module scriptblock with automatic retry on throttling (429) and transient errors (5xx).

    .DESCRIPTION
    Wraps any Az module call in a retry loop with linear backoff. On HTTP 429 (TooManyRequests) or
    transient server errors (500, 502, 503, 504), the call is retried up to MaxRetries times,
    waiting RetryDelaySec * attempt seconds between each retry. Non-retriable errors are re-thrown
    immediately without consuming retry attempts.

    .PARAMETER ScriptBlock
    The Az module call to execute, wrapped in a scriptblock.

    .PARAMETER OperationName
    Descriptive name for the operation, used in warning messages. Defaults to 'Azure API call'.

    .PARAMETER MaxRetries
    Maximum number of retry attempts. Must be between 1 and 10. Default: 3.

    .PARAMETER RetryDelaySec
    Base delay in seconds between retries (multiplied by attempt number: 1x, 2x, 3x...).
    Must be between 1 and 60. Default: 5.

    .EXAMPLE
    Invoke-AzWithRetry -OperationName 'Get-AzResourceGroup' -ScriptBlock {
        Get-AzResourceGroup -ErrorAction Stop
    }

    .EXAMPLE
    $result = Invoke-AzWithRetry -ScriptBlock { Get-AzSubscription -ErrorAction Stop } -MaxRetries 5 -RetryDelaySec 10
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [string]$OperationName = 'Azure API call',

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySec = 5
    )

    $attempt = 0

    while ($true) {
        $attempt++
        try {
            return (& $ScriptBlock)
        }
        catch {
            $errMsg = $_.Exception.Message

            $isThrottling = $errMsg -match '429|TooManyRequests|throttl'
            $isTransient  = $errMsg -match '500|502|503|504|ServiceUnavailable|InternalServerError'

            if (($isThrottling -or $isTransient) -and $attempt -le $MaxRetries) {
                $wait = $RetryDelaySec * $attempt
                Write-Warning "  [Retry $attempt/$MaxRetries] $OperationName - $errMsg. Waiting ${wait}s..."
                Start-Sleep -Seconds $wait
                continue
            }

            throw
        }
    }
}
