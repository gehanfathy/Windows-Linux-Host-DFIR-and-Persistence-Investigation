# Windows Collector - Output Validation
# Read-only validation of collected JSONL files.

$ErrorActionPreference = "Stop"

$OutputDirectory = "C:\Windows-Collector\sample_data\windows"

$RequiredFiles = @(
    "security_events.jsonl",
    "scheduled_tasks.jsonl",
    "services.jsonl",
    "registry_run_keys.jsonl",
    "powershell_operational.jsonl",
    "sysmon_events.jsonl"
)

$Results = @()
$AllPassed = $true

foreach ($FileName in $RequiredFiles) {

    $FilePath = Join-Path $OutputDirectory $FileName

    if (-not (Test-Path -LiteralPath $FilePath)) {
        $Results += [PSCustomObject]@{
            File = $FileName
            Records = 0
            InvalidJSON = 0
            Status = "FAIL - File Missing"
        }
        $AllPassed = $false
        continue
    }

    $Total = 0
    $Invalid = 0
    $MissingFields = 0

    foreach ($Line in Get-Content -LiteralPath $FilePath) {

        if ([string]::IsNullOrWhiteSpace($Line)) {
            continue
        }

        $Total++

        try {
            $Record = $Line | ConvertFrom-Json -ErrorAction Stop

            if ($FileName -eq "security_events.jsonl") {
                if (
                    $null -eq $Record.event_id -or
                    $null -eq $Record.record_id -or
                    [string]::IsNullOrWhiteSpace($Record.timestamp) -or
                    [string]::IsNullOrWhiteSpace($Record.provider)
                ) {
                    $MissingFields++
                }
            }
            elseif (
                $null -eq $Record.collection_type -or
                [string]::IsNullOrWhiteSpace($Record.host_id) -or
                [string]::IsNullOrWhiteSpace($Record.timestamp)
            ) {
                $MissingFields++
            }
        }
        catch {
            $Invalid++
        }
    }

    $Status = "PASS"

    if ($Total -eq 0 -or $Invalid -gt 0 -or $MissingFields -gt 0) {
        $Status = "FAIL"
        $AllPassed = $false
    }

    $Results += [PSCustomObject]@{
        File = $FileName
        Records = $Total
        InvalidJSON = $Invalid
        MissingFields = $MissingFields
        Status = $Status
    }
}

$Results | Format-Table -AutoSize

# Validate required Security Event IDs.
$SecurityPath = Join-Path $OutputDirectory "security_events.jsonl"

if (Test-Path -LiteralPath $SecurityPath) {

    $SecurityEvents = Get-Content -LiteralPath $SecurityPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json }

    $Event4624 = @($SecurityEvents | Where-Object { $_.event_id -eq 4624 }).Count
    $Event4625 = @($SecurityEvents | Where-Object { $_.event_id -eq 4625 }).Count

    Write-Host "Event 4624 count: $Event4624"
    Write-Host "Event 4625 count: $Event4625"

    if ($Event4624 -eq 0 -or $Event4625 -eq 0) {
        $AllPassed = $false
    }
}

if ($AllPassed) {
    Write-Host "`nOVERALL RESULT: PASS" -ForegroundColor Green
}
else {
    Write-Host "`nOVERALL RESULT: FAIL" -ForegroundColor Red
}