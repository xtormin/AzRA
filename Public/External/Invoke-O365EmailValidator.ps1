# Author: Xtormin (Jennifer Torres)
# Github: https://github.com/xtormin
# Description: This script validates a list of email addresses by checking their existence in Office 365 without submitting login attempts.

# Import: . .\O365EmailValidator.ps1

function Invoke-O365EmailValidator {
    <#
    .SYNOPSIS
    This script validates a list of email addresses by checking their existence in Office 365 without submitting login attempts.

    .DESCRIPTION
    The script takes a file containing a list of email addresses as input and validates each email address by making a REST request to Office 365. It checks whether the email address exists in Office 365 without actually attempting to log in. The result, along with the email address, is then outputted. Additionally, the script supports filtering the output to only show email addresses that exist or showing all email addresses.

    .PARAMETER File
    Specifies the path to the file containing the list of email addresses to be validated.

    .PARAMETER Output
    Specifies the path to the file where the output will be written. If not specified, the output will be displayed in the console.

    .EXAMPLE
    Invoke-O365EmailValidator -File "emails.txt" -Output "validation_result.txt"
    This command validates the email addresses listed in "emails.txt" and writes the validation results to "validation_result.txt".

    .AUTHOR
    Xtormin (Jennifer Torres)

    Github: https://github.com/xtormin
    Twitter: https://twitter.com/xtormin
    Linkedin: https://www.linkedin.com/in/xtormin/
    #>


    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$File,

        [string]$Output
    )

    function Validate-Email {
        param (
            [Parameter(Mandatory=$true)]
            [string]$User
        )

        try {
            $Exists = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/GetCredentialType" -ContentType "application/json" -Method POST -Body (@{"username"="$User"; "isOtherIdpSupported" =  $true}|ConvertTo-Json) | Select -ExpandProperty IfExistsResult
            [PSCustomObject]@{Username = $User; Exists = ($Exists -eq 0 -or $Exists -eq 6)}
        }
        catch {
            Write-Error "|-| Failed to validate email address: $_"
        }
    }

    function Write-OutputToFile {
        param (
            [Parameter(Mandatory=$true)]
            [string]$OutputString,

            [Parameter(Mandatory=$true)]
            [string]$OutputFile
        )

        try {
            $OutputString | Out-File -FilePath $OutputFile -Append
        }
        catch {
            Write-Error "|-| Failed to write to output file: $_"
        }
    }

    try {
        $Users = Get-Content -Path $File -ErrorAction Stop

        foreach ($User in $Users) {
            $Result = Validate-Email -User $User
            $OutputString = "$($Result.Username)"

            if ($Result.Exists) {
                if ($Output) {
                    Write-OutputToFile -OutputString $OutputString -OutputFile $Output
                }
                else {
                    Write-Output $OutputString
                }
            }
        }
    }
    catch {
        Write-Error "|-| An error occurred: $_"
    }
}