# ==========================================
# Windows Collector
# Read-Only Evidence Collection
# ==========================================

param(
    [string]$OutputPath = "C:\Windows-Collector\sample_data\windows\security_events.jsonl"
)

$ErrorActionPreference = "Stop"

# Collection Configuration
$EventIDs = @(4624, 4625)

$HostID = $env:COMPUTERNAME

$CollectionTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "Windows Collector Started"
Write-Host "Host ID: $HostID"
Write-Host "Collection Time (UTC): $CollectionTime"
Write-Host "Target Events: 4624, 4625"
# ==========================================
# Collect Security Events
# ==========================================

Write-Host "`nCollecting Security Events..."

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID      = $EventIDs
} -ErrorAction SilentlyContinue

if ($null -eq $Events) {
    Write-Host "No matching events found."
}
else {
    Write-Host "Found $($Events.Count) events."
}
# ==========================================
# Convert Events to JSONL
# ==========================================

$OutputDirectory = Split-Path $OutputPath -Parent

if (!(Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$JsonLines = foreach ($Event in $Events) {

    $Xml = [xml]$Event.ToXml()
    $EventData = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $EventData[$Item.Name] = $Item.InnerText
    }

    $Timestamp = $Event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $Record = [PSCustomObject]@{
        collection_type = "windows_security_event"
        host_id         = $HostID
        event_id        = $Event.Id
        record_id       = $Event.RecordId
        timestamp       = $Timestamp
        provider        = $Event.ProviderName
        message         = $Event.Message
        data            = @{
            target_username = $EventData["TargetUserName"]
            ip_address      = $EventData["IpAddress"]
        }
    }

    $Record | ConvertTo-Json -Depth 5 -Compress
}

if ($JsonLines) {
    $JsonLines | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "Output saved successfully: $OutputPath"
}


# ==========================================
# Collect Scheduled Tasks (Read-Only)
# ==========================================

Write-Host "`nCollecting Scheduled Tasks..."

$ScheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue

$TaskRecords = foreach ($Task in $ScheduledTasks) {

    foreach ($Action in $Task.Actions) {

        $ActionType = $Action.CimClass.CimClassName

        $ExecutablePath = $null
        $Arguments = $null
        $WorkingDirectory = $null
        $ClassId = $null
        $ComData = $null

        if ($ActionType -eq "MSFT_TaskExecAction") {
            $ExecutablePath = $Action.Execute
            $Arguments = $Action.Arguments
            $WorkingDirectory = $Action.WorkingDirectory
        }
        elseif ($ActionType -eq "MSFT_TaskComHandlerAction") {
            $ClassId = [string]$Action.ClassId
            $ComData = $Action.Data
        }

        [PSCustomObject]@{
            collection_type    = "windows_scheduled_task"
            host_id            = $HostID
            timestamp          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            task_name          = $Task.TaskName
            task_path          = $Task.TaskPath
            author             = $Task.Author
            action_type        = $ActionType
            executable_path    = $ExecutablePath
            arguments          = $Arguments
            working_directory  = $WorkingDirectory
            com_class_id       = $ClassId
            com_data           = $ComData
            run_as_user        = $Task.Principal.UserId
            logon_type         = $Task.Principal.LogonType.ToString()
            run_level          = $Task.Principal.RunLevel.ToString()
        } | ConvertTo-Json -Depth 5 -Compress
    }
}

$TaskOutputPath = "C:\Windows-Collector\sample_data\windows\scheduled_tasks.jsonl"

if ($TaskRecords) {
    $TaskRecords | Set-Content -Path $TaskOutputPath -Encoding UTF8
    Write-Host "Scheduled Tasks saved: $TaskOutputPath"
    Write-Host "Total Actions collected: $($TaskRecords.Count)"
}
else {
    Write-Host "No Scheduled Task Actions found."
}




# ==========================================
# Windows Services Collection (Read-Only)
# ==========================================

$ServiceRecords = Get-CimInstance -ClassName Win32_Service |
ForEach-Object {
    [PSCustomObject]@{
        collection_type = "windows_service"
        host_id         = $HostID
        timestamp       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        name            = $_.Name
        display_name    = $_.DisplayName
        status          = $_.State
        start_type      = $_.StartMode
        binary_path     = $_.PathName
        account         = $_.StartName
    }
}

$ServiceOutputPath = "C:\Windows-Collector\sample_data\windows\services.jsonl"

if ($ServiceRecords) {
    $ServiceRecords | ForEach-Object {

    $_ | ConvertTo-Json -Depth 5 -Compress

} | Set-Content -Path $ServiceOutputPath -Encoding UTF8

    Write-Host "Windows Services saved: $ServiceOutputPath"
    Write-Host "Total Services collected: $($ServiceRecords.Count)"
}
else {
    Write-Host "No Windows Services found."
} 



# ==========================================
# Registry Run Keys Collection (Read-Only)
# ==========================================

$RegistryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)

$RegistryRecords = foreach ($Path in $RegistryPaths) {

    if (Test-Path -LiteralPath $Path) {

        try {
            $Key = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop

            foreach ($Property in $Key.PSObject.Properties) {

                if ($Property.Name -notin @(
                    "PSPath",
                    "PSParentPath",
                    "PSChildName",
                    "PSDrive",
                    "PSProvider"
                )) {

                    [PSCustomObject]@{
                        collection_type = "windows_registry_run"
                        host_id         = $HostID
                        timestamp       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                        registry_path   = $Path
                        value_name      = $Property.Name
                        value_data      = [string]$Property.Value
                    }
                }
            }
        }
        catch {
            Write-Warning "Unable to read registry path: $Path"
        }
    }
    else {
        Write-Host "Registry path not available: $Path"
    }
}

$RegistryOutputPath = "C:\Windows-Collector\sample_data\windows\registry_run_keys.jsonl"

if ($RegistryRecords) {
    $RegistryRecords | ForEach-Object {
        $_ | ConvertTo-Json -Depth 5 -Compress
    } | Set-Content -Path $RegistryOutputPath -Encoding UTF8

    Write-Host "Registry Run Keys saved: $RegistryOutputPath"
    Write-Host "Total Registry Records: $($RegistryRecords.Count)"
}
else {
    Write-Host "No Registry Run Values found."
}


# ==========================================
# PowerShell Operational Logs (Read-Only)
# ==========================================

$PowerShellLogName = "Microsoft-Windows-PowerShell/Operational"
$PowerShellOutputPath = "C:\Windows-Collector\sample_data\windows\powershell_operational.jsonl"

try {
    $PowerShellLog = Get-WinEvent -ListLog $PowerShellLogName -ErrorAction Stop

    if ($PowerShellLog.IsEnabled) {

        $PowerShellRecords = Get-WinEvent -LogName $PowerShellLogName -ErrorAction Stop |
        ForEach-Object {
            [PSCustomObject]@{
                collection_type = "windows_powershell_event"
                host_id         = $HostID
                event_id        = $_.Id
                record_id       = $_.RecordId
                timestamp       = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                provider        = $_.ProviderName
                level           = $_.LevelDisplayName
            }
        }

        $PowerShellRecords | ForEach-Object {
            $_ | ConvertTo-Json -Depth 5 -Compress
        } | Set-Content -Path $PowerShellOutputPath -Encoding UTF8

        Write-Host "PowerShell Operational Logs saved: $PowerShellOutputPath"
        Write-Host "Total PowerShell Events: $($PowerShellRecords.Count)"
    }
    else {
        Write-Host "PowerShell Operational Log is disabled. No changes made."
    }
}
catch {
    Write-Warning "Unable to collect PowerShell Operational Logs: $($_.Exception.Message)"
}



# ==========================================
# Sysmon Events Collection (Read-Only)
# ==========================================

$SysmonLogName = "Microsoft-Windows-Sysmon/Operational"
$SysmonOutputPath = "C:\Windows-Collector\sample_data\windows\sysmon_events.jsonl"

try {
    $SysmonLog = Get-WinEvent -ListLog $SysmonLogName -ErrorAction Stop

    if ($SysmonLog.IsEnabled) {

        $SysmonRecords = Get-WinEvent -LogName $SysmonLogName -ErrorAction Stop |
        ForEach-Object {
            [PSCustomObject]@{
                collection_type = "windows_sysmon_event"
                host_id         = $HostID
                event_id        = $_.Id
                record_id       = $_.RecordId
                timestamp       = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                provider        = $_.ProviderName
                level           = $_.LevelDisplayName
            }
        }

        $SysmonRecords | ForEach-Object {
            $_ | ConvertTo-Json -Depth 5 -Compress
        } | Set-Content -Path $SysmonOutputPath -Encoding UTF8

        Write-Host "Sysmon Events saved: $SysmonOutputPath"
        Write-Host "Total Sysmon Events: $($SysmonRecords.Count)"
    }
    else {
        Write-Host "Sysmon Operational Log is disabled. No changes made."
    }
}
catch {
    Write-Warning "Unable to collect Sysmon Events: $($_.Exception.Message)"
}


