<#
.SYNOPSIS
    Read-only Windows evidence collector for the DFIR & Persistence
    Investigation project.

.DESCRIPTION
    Collects the following evidence from the LOCAL machine only, and writes
    JSON output files into -OutputDir (default: .\output\windows):

      1. Security events 4624 / 4625 / 4720 / 4732 / 1102  -> security_events.jsonl
      2. Scheduled tasks (name, author, action, run-as)    -> scheduled_tasks.json
      3. Services (name, status, start type, binary path)  -> services.json
      4. Registry Run keys (HKLM + HKCU, read only)        -> registry_runkeys.json
      5. A collection summary / audit of what was gathered -> collection_summary.json

    SAFETY RULES (per team guide 03):
      - READ-ONLY: uses Get-* cmdlets only. Never clears logs, never edits
        the registry, never stops services, never creates tasks.
      - No passwords, tokens or private keys are collected.
      - If a source is unavailable (no permission / missing), it is logged
        in collection_summary.json instead of fabricating data.

.PARAMETER OutputDir
    Folder where the JSON output files are written.

.PARAMETER MaxEvents
    Maximum number of security events to collect (default 500).

.EXAMPLE
    # PowerShell "Run as Administrator" is recommended (Security log access)
    Set-ExecutionPolicy -Scope Process Bypass
    .\collectors\windows\collector.ps1 -OutputDir .\output\windows -MaxEvents 500
#>

[CmdletBinding()]
param(
    [string]$OutputDir = ".\output\windows",
    [int]$MaxEvents = 500
)

$ErrorActionPreference = "Continue"

$ComputerName = $env:COMPUTERNAME
$CollectedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$summary = [ordered]@{
    host_id      = $ComputerName
    collected_at = $CollectedAt
    mode         = "read-only"
    sources      = @()
}

function Get-UtcIso {
    param($DateTime)
    $DateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

# ============================================================
# 1) Security Event Log (4624 / 4625 / 4720 / 4732 / 1102)
# ============================================================
$sourceName = "Security Event Log (4624/4625/4720/4732/1102)"
try {
    $filter = @{ LogName = "Security"; Id = 4624, 4625, 4720, 4732, 1102 }
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop

    $path = Join-Path $OutputDir "security_events.jsonl"
    $count = 0

    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        if ($xml.Event.EventData -and $xml.Event.EventData.Data) {
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $data[$d.Name] = $d."#text" }
            }
        }

        $targetUsername = $data["TargetUserName"]
        $groupName = ""

        if ($e.Id -eq 4732) {
            # 4732: MemberName = account added, TargetUserName = group name
            $targetUsername = $data["MemberName"]
            $groupName = $data["TargetUserName"]
        }

        $record = [ordered]@{
            collection_type = "windows_security_event"
            host_id         = $ComputerName
            event_id        = $e.Id
            record_id       = $e.RecordId
            timestamp       = Get-UtcIso $e.TimeCreated
            provider        = $e.ProviderName
            message         = (($e.Message -split "`n")[0]).Trim()
            data            = [ordered]@{
                target_username  = $targetUsername
                subject_username = $data["SubjectUserName"]
                group_name       = $groupName
                source_ip        = $data["IpAddress"]
                logon_type       = $data["LogonType"]
                workstation_name = $data["WorkstationName"]
                status_code      = $data["Status"]
            }
        }

        $json = $record | ConvertTo-Json -Compress -Depth 5
        Add-Content -Path $path -Value $json -Encoding UTF8
        $count++
    }

    if ($count -gt 0) {
        $summary.sources += [ordered]@{
            name   = $sourceName
            status = "collected"
            count  = $count
            output = (Resolve-Path $path).Path
        }
    }
    else {
        $summary.sources += [ordered]@{
            name   = $sourceName
            status = "empty"
            error  = "No matching events found"
        }
    }
}
catch {
    $summary.sources += [ordered]@{
        name   = $sourceName
        status = "error"
        error  = $_.Exception.Message
    }
}

# ============================================================
# 2) Scheduled Tasks (read only)
# ============================================================
$sourceName = "Scheduled Tasks"
try {
    $tasks = @()
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $t = $_
        foreach ($a in $t.Actions) {
            $tasks += [ordered]@{
                name      = $t.TaskName
                path      = $t.TaskPath
                author    = $t.Author
                status    = [string]$t.State
                run_as    = [string]$t.Principal.UserId
                task_file = ("{0}{1}" -f $t.TaskPath, $t.TaskName)
                actions   = @([ordered]@{
                    execute   = [string]$a.Execute
                    arguments = [string]$a.Arguments
                })
            }
        }
    }

    $doc = [ordered]@{
        collection_type = "windows_scheduled_tasks"
        host_id         = $ComputerName
        collected_at    = $CollectedAt
        items           = $tasks
    }
    $path = Join-Path $OutputDir "scheduled_tasks.json"
    $doc | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8

    $summary.sources += [ordered]@{
        name   = $sourceName
        status = "collected"
        count  = @($tasks).Count
        output = (Resolve-Path $path).Path
    }
}
catch {
    $summary.sources += [ordered]@{
        name   = $sourceName
        status = "error"
        error  = $_.Exception.Message
    }
}

# ============================================================
# 3) Services (read only)
# ============================================================
$sourceName = "Windows Services"
try {
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
        ForEach-Object {
            [ordered]@{
                name         = $_.Name
                display_name = $_.DisplayName
                status       = $_.State
                start_type   = $_.StartMode
                account      = $_.StartName
                binary_path  = $_.PathName
            }
        }

    $doc = [ordered]@{
        collection_type = "windows_services"
        host_id         = $ComputerName
        collected_at    = $CollectedAt
        items           = @($services)
    }
    $path = Join-Path $OutputDir "services.json"
    $doc | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8

    $summary.sources += [ordered]@{
        name   = $sourceName
        status = "collected"
        count  = @($services).Count
        output = (Resolve-Path $path).Path
    }
}
catch {
    $summary.sources += [ordered]@{
        name   = $sourceName
        status = "error"
        error  = $_.Exception.Message
    }
}

# ============================================================
# 4) Registry Run Keys (HKLM + HKCU, read only)
# ============================================================
$sourceName = "Registry Run Keys (HKLM/HKCU)"
try {
    $runKeys = @()
    $runKeyPaths = @(
        @{ hive = "HKLM"; key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ hive = "HKCU"; key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" }
    )

    foreach ($p in $runKeyPaths) {
        $full = "{0}:\{1}" -f $p.hive, $p.key
        if (Test-Path $full) {
            $props = Get-ItemProperty -Path $full -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -like "PS*") { continue }
                $runKeys += [ordered]@{
                    hive       = $p.hive
                    key        = $p.key
                    value_name = $prop.Name
                    command    = [string]$prop.Value
                }
            }
        }
    }

    $doc = [ordered]@{
        collection_type = "windows_registry_runkeys"
        host_id         = $ComputerName
        collected_at    = $CollectedAt
        items           = @($runKeys)
    }
    $path = Join-Path $OutputDir "registry_runkeys.json"
    $doc | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8

    $summary.sources += [ordered]@{
        name   = $sourceName
        status = "collected"
        count  = @($runKeys).Count
        output = (Resolve-Path $path).Path
    }
}
catch {
    $summary.sources += [ordered]@{
        name   = $sourceName
        status = "error"
        error  = $_.Exception.Message
    }
}

# ============================================================
# 5) Collection summary (audit of the collection itself)
# ============================================================
$summaryPath = Join-Path $OutputDir "collection_summary.json"
$summary | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "Collection finished (READ-ONLY - nothing was modified)." -ForegroundColor Green
foreach ($s in $summary.sources) {
    Write-Host (" - {0}: {1}" -f $s.name, $s.status)
}
Write-Host (" Output directory: {0}" -f (Resolve-Path $OutputDir).Path)
