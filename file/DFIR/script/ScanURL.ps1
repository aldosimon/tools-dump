<#
.SYNOPSIS
    Checks a URL against VirusTotal and URLscan.io and displays only the verdict.

.DESCRIPTION
    This script takes a URL as input, submits it to VirusTotal and URLscan.io
    for analysis, and then retrieves and displays the verdict from each service.
    It requires API keys for both VirusTotal and URLscan.io to function correctly.
    You can obtain API keys from:
    - VirusTotal: https://developers.virustotal.com/reference/apikey
    - URLscan.io: https://urlscan.io/docs/api/

.PARAMETER URL
    The URL to be checked. If not provided as a parameter, the script will prompt for it.

.PARAMETER VirusTotalApiKey
    Your VirusTotal API key.

.PARAMETER URLscanApiKey
    Your URLscan.io API key.

.EXAMPLE
    .\Check-URLVerdict.ps1 -URL "http://example.com" -VirusTotalApiKey "YOUR_VIRUSTOTAL_API_KEY" -URLscanApiKey "YOUR_URLSCANIO_API_KEY"

.NOTES
    - Ensure you have PowerShell version 5.1 or later for optimal compatibility.
    - The script handles basic errors but more robust error handling can be added.
    - Be mindful of the API request limits for both services.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$URL,

    [Parameter(Mandatory=$false)]
    [string]$VirusTotalApiKey,

    [Parameter(Mandatory=$false)]
    [string]$URLscanApiKey
)

# Prompt for URL if not provided
if (-not $URL) {
    $URL = Read-Host "Enter the URL to check"
}

# --- Function to Check URL on VirusTotal ---
function Check-VirusTotal {
    param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$ApiKey
    )

    Write-Host "Checking VirusTotal for '$URL'..."

    if (-not $ApiKey) {
        Write-Warning "VirusTotal API key not provided. Skipping VirusTotal check."
        return "VirusTotal: API key not provided"
    }

    try {
        # Submit URL for analysis
        $Uri = "https://www.virustotal.com/api/v3/urls"
        $Headers = @{
                    "Accept"       = "application/json"
                    'X-Apikey'     = $ApiKey
                    "Content-Type" = "application/x-www-form-urlencoded"
        }
        $Body = @{'url' = [uri]::EscapeUriString($URL)} #| ConvertTo-Json
        $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body #-Headers "application/json"

        if ($Response.data.id) {
            Write-Host "URL submitted to VirusTotal. Waiting for analysis..."
            Start-Sleep -Seconds 30 # Give some time for analysis

            # Get analysis results
            $AnalysisUri = "https://www.virustotal.com/api/v3/analyses/$($Response.data.id)"
            $AnalysisResponse = Invoke-RestMethod -Method Get -Uri $AnalysisUri -Headers $Headers -ContentType "application/json"

            if ($AnalysisResponse.data.attributes.stats.malicious -gt 0) {
                return "VirusTotal: Malicious"
            } elseif ($AnalysisResponse.data.attributes.stats.suspicious -gt 0) {
                return "VirusTotal: Suspicious"
            } else {
                return "VirusTotal: Clean"
            }
        } else {
            return "VirusTotal: Error submitting URL"
        }
    } catch {
        return "VirusTotal: Error - $($_.Exception.Message)"
    }
}

# --- Function to Check URL on URLscan.io ---
function Check-URLscan {
    param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$ApiKey
    )

    Write-Host "Checking URLscan.io for '$URL'..."

    if (-not $ApiKey) {
        Write-Warning "URLscan.io API key not provided. Skipping URLscan.io check."
        return "URLscan.io: API key not provided"
    }

    try {
        $Uri = "https://urlscan.io/api/v1/scan/"
        $Headers = @{}
        if ($ApiKey) {
            $Headers["API-Key"] = $ApiKey
        }
        $Body = @{"url" = $URL} | ConvertTo-Json
        $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -Body $Body -ContentType "application/json"

        if ($Response.result) {
            Write-Host "URL submitted to URLscan.io. Waiting for analysis..."
            Start-Sleep -Seconds 30 # Give some time for analysis

            $ResultUri = "https://urlscan.io/api/v1/result/$($Response.uuid)"
            $ResultResponse = Invoke-RestMethod -Method Get -Uri $ResultUri -Headers $Headers -ContentType "application/json"

            if ($ResultResponse.verdict.malicious -eq $true) {
                return "URLscan.io: Malicious"
            } elseif ($ResultResponse.verdict.suspicious -eq $true) {
                return "URLscan.io: Suspicious"
            } else {
                return "URLscan.io: Clean"
            }
        } else {
            return "URLscan.io: Error submitting URL"
        }
    } catch {
        return "URLscan.io: Error - $($_.Exception.Message)"
    }
}

# --- Main Script ---
Write-Host "Starting URL check..."

$VirusTotalResult = Check-VirusTotal -URL $URL -ApiKey $VirusTotalApiKey
Write-Host $VirusTotalResult

$URLscanResult = Check-URLscan -URL $URL -ApiKey $URLscanApiKey
Write-Host $URLscanResult

Write-Host "URL check completed."