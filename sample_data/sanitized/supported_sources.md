# Windows Collector – Supported Sources and Event IDs

## 1. Security Events

Log: `Security`

| Event ID | Description | Status |
|---|---|---|
| 4624 | Successful Logon | Implemented |
| 4625 | Failed Logon | Implemented |
| 4720 | User Created | Not Implemented |
| 4732 | Member Added to Local Group | Not Implemented |
| 1102 | Audit Log Cleared | Not Implemented |

The current first deliverable collects Event IDs 4624 and 4625 only.

Collected fields include:
- Event ID
- Record ID
- UTC Timestamp
- Provider
- Event Message
- Available Username and IP Address fields

## 2. PowerShell Operational Logs

Log: `Microsoft-Windows-PowerShell/Operational`

Status: Implemented when available.

Collection includes event metadata:
- Event ID
- Record ID
- UTC Timestamp
- Provider
- Level

Event messages and event data are not collected.

## 3. Scheduled Tasks

Source: Windows Scheduled Tasks

Status: Implemented.

Collected fields include:
- Task Name
- Task Path
- Author
- Action Type
- Executable Path
- Arguments
- Working Directory
- Run-As User
- Logon Type
- Run Level

Executable actions and COM handler actions are supported.

## 4. Windows Services

Source: `Win32_Service`

Status: Implemented.

Collected fields:
- Name
- Display Name
- Status
- Start Type
- Binary Path
- Account

## 5. Registry Run Keys

Status: Implemented with read-only access.

Registry paths:
- `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`

Collected fields:
- Registry Path
- Value Name
- Value Data

Review and sanitize values before sharing sample data.

## 6. Sysmon Events

Log: `Microsoft-Windows-Sysmon/Operational`

Status: Implemented when Sysmon is installed and the log is available.

Collection includes metadata only:
- Event ID
- Record ID
- UTC Timestamp
- Provider
- Level

Event messages and event data are not collected.

## 7. Collection Limitations

- Collection completeness depends on permissions and source availability.
- Event IDs 4720, 4732, and 1102 are not implemented.
- Missing sources must be reported rather than represented by fabricated records.
- The collector does not perform security analysis or assign threat classifications.
- Raw Lab output must not be uploaded publicly without sanitization.