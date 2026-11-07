# Windows Evidence Collector

## 1. Project Overview

The Windows Evidence Collector is a PowerShell-based tool designed to collect Windows system evidence in a read-only manner.

The collector retrieves system information and event metadata and stores the collected output locally in JSONL format for later parsing and analysis.

**Important:** The collector does not perform security analysis, assign threat classifications, or modify collected system evidence.

## 2. Environment Requirements

- Windows 10 / Windows 11.
- Windows PowerShell 5.1 or later.
- Administrator privileges recommended for accessing protected Windows Event Logs and collecting complete evidence.
- PowerShell ScheduledTasks module.
- Local write access to the project directory.

## 3. Supported Data Sources

| Data Source | Collected Information | Output File |
|---|---|---|
| Security Events | Event ID, Record ID, UTC Timestamp, Provider, Message, Username, IP Address | security_events.jsonl |
| Scheduled Tasks | Task Name, Task Path, Author, Action, Executable Path, Run-As User | scheduled_tasks.jsonl |
| Windows Services | Name, Display Name, Status, Start Type, Binary Path, Account | services.jsonl |
| Registry Run Keys | Registry Path, Value Name, Value Data | registry_run_keys.jsonl |
| PowerShell Operational | Event ID, Record ID, UTC Timestamp, Provider, Level | powershell_operational.jsonl |
| Sysmon | Event ID, Record ID, UTC Timestamp, Provider, Level | sysmon_events.jsonl |

### Security Event IDs

The initial Security Events collection scope is:

- 4624 – Successful Logon
- 4625 – Failed Logon

Other requested event IDs for future extension:

- 4720 – User Account Created
- 4732 – Member Added to Local Group
- 1102 – Audit Log Cleared

### Scheduled Tasks

Supported action types currently include:

- MSFT_TaskExecAction
- MSFT_TaskComHandlerAction

COM Handler actions are represented using their Class ID and associated data.

### Registry

The collector reads the following Run keys:

- HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
- HKLM:\Software\Microsoft\Windows\CurrentVersion\Run

HKCU refers to the account running the collector.

### Optional Event Sources

PowerShell Operational and Sysmon are collected only when their event logs are available and enabled.

PowerShell Operational and Sysmon currently collect event metadata, not full event messages or event payloads.

## 4. Project Structure

```text
Windows-Collector/
│
├── collectors/
│   └── windows/
│       ├── collector.ps1
│       └── README.md
│
├── tests/
│   └── collectors/
│       └── windows/
│
└── sample_data/
    └── windows/
        ├── security_events.jsonl
        ├── scheduled_tasks.jsonl
        ├── services.jsonl
        ├── registry_run_keys.jsonl
        ├── powershell_operational.jsonl
        └── sysmon_events.jsonl
```

## 5. How to Run

Open Windows PowerShell with appropriate permissions.

Run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

Execute the collector:

```powershell
& "C:\Windows-Collector\collectors\windows\collector.ps1"
```

The collector saves its output locally under:

```text
C:\Windows-Collector\sample_data\windows\
```

## 6. Output Format

All collected records are intended to use JSON Lines (JSONL).

Each line represents one independent JSON record.

Example:

```json
{
  "collection_type": "windows_service",
  "host_id": "PC0",
  "timestamp": "2026-11-05T19:19:30Z",
  "name": "ExampleService",
  "display_name": "Example Service",
  "status": "Running",
  "start_type": "Auto",
  "binary_path": "C:\\Windows\\System32\\example.exe",
  "account": "LocalSystem"
}
```

The example above is illustrative and does not represent an actual collected service.

## 7. Safety and Read-Only Rules

The collector follows these rules:

1. Does not modify Windows Registry keys or values.
2. Does not modify Audit Policies.
3. Does not clear or disable Windows Event Logs.
4. Does not create or modify permanent Windows Scheduled Tasks.
5. Does not collect passwords, authentication tokens, or private keys.
6. Stores collected evidence locally.
7. Does not automatically upload collected data to GitHub or external services.
8. Reports unavailable sources instead of inventing evidence.

The collector writes its own output files. This is the only intended persistent write operation during collection.

## 8. Validation and Lab Testing

The following checks have been performed during development:

- Security Events 4624 and 4625 collection.
- JSONL parsing validation.
- Record ID and UTC Timestamp checks.
- Scheduled Task collection.
- Temporary Scheduled Task execution test using WINDOWS-COLLECT-TEST-001.
- Verification of the temporary task's timestamp output.
- Removal of the temporary Scheduled Task and test files.
- Windows Services collection and required-field validation.
- Registry Run Keys collection and required-field validation.
- PowerShell Operational collection and JSONL validation.
- Sysmon collection and JSONL validation.

Observed Lab collection counts during testing:

| Source | Observed Records |
|---|---:|
| Security Events | 1054 |
| Scheduled Tasks | 233 |
| Windows Services | 265 |
| Registry Run Keys | 4 |
| PowerShell Operational | 181 |
| Sysmon | 1562 |

Counts are environment-dependent and may change between executions.

## 9. Current Limitations

- Security Events currently target only Event IDs 4624 and 4625.
- Event IDs 4720, 4732, and 1102 have not yet been implemented.
Operational and Sysmon collectors currently store event metadata only; event messages and event data are not collected.

- Scheduled Tasks collection supports executable actions and COM handler actions. Some fields may be empty when they are not provided by Windows.
- Registry Run Key values are collected as-is and may contain command-line arguments or sensitive paths. Review and redact them before sharing sample data.
- Collection completeness depends on Windows permissions, available event logs, and system configuration.
- The collector writes output files locally. It does not guarantee that all possible Windows evidence sources are available.

## 10. Delivery Notes

The delivery package should include:

1. `collectors/windows/collector.ps1`
2. `collectors/windows/README.md`
3. Sanitized sample Security Events for Event IDs 4624 and 4625.
4. A list of supported Event IDs and data sources.
5. Repeatable validation steps or test scripts.

Do not upload raw Lab output containing real usernames, IP addresses, registry values, or other sensitive information to GitHub. Use sanitized sample data only.

The collector is intended to be run by another team member on a Windows Lab machine. The resulting JSONL files should be available for downstream parsing without modifying the machine's security configuration or collected evidence.