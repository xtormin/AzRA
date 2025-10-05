# AzRA.psm1
# Author: Xtormin (Jennifer Torres)
# Twitter: https://twitter.com/xtormin
# Description: PowerShell module for Azure and Microsoft 365 security reconnaissance and testing.

# Import Private functions (helpers) first
$PrivatePath = Join-Path $PSScriptRoot 'Private'
if (Test-Path $PrivatePath) {
    Get-ChildItem -Path "$PrivatePath\*.ps1" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Verbose "Importing private function: $($_.Name)"
        . $_.FullName
    }
}

# Import Public functions (Internal + External reconnaissance)
$PublicPath = Join-Path $PSScriptRoot 'Public'
if (Test-Path $PublicPath) {
    # Import from Public/Internal
    $InternalPath = Join-Path $PublicPath 'Internal'
    if (Test-Path $InternalPath) {
        Get-ChildItem -Path "$InternalPath\*.ps1" -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Verbose "Importing internal function: $($_.Name)"
            . $_.FullName
        }
    }

    # Import from Public/External
    $ExternalPath = Join-Path $PublicPath 'External'
    if (Test-Path $ExternalPath) {
        Get-ChildItem -Path "$ExternalPath\*.ps1" -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Verbose "Importing external function: $($_.Name)"
            . $_.FullName
        }
    }
}

# Export all public functions (Get-AzRA-*, Invoke-*, Request-*)
Export-ModuleMember -Function *-AzRA-*, Invoke-O365EmailValidator