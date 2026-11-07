# Windows Collector — Read-Only Evidence Collection

Collects Windows evidence as raw JSON output for the DFIR pipeline.
The collector **never modifies the system**: it only reads.

## Requirements

- Windows 10 / 11 or Windows Server 2016+
- Windows PowerShell 5.1 (built in) or newer
- Run **as Administrator** (recommended) — reading the `Security` event log
  requires local admin or `Event Log Readers` membership
- No external dependencies

## What it collects

| Source | Output file | Content |
|---|---|---|
| Security Event Log | `security_events.jsonl` | Events `4624` (successful logon), `4625` (failed logon), `4720` (user created), `4732` (added to local group), `1102` (audit log cleared) |
| Scheduled Tasks | `scheduled_tasks.json` | Task name, path, author, state, run-as user, action executable + arguments |
| Services | `services.json` | Service name, display name, status, start type, account, binary path |
| Registry Run Keys | `registry_runkeys.json` | `HKLM` / `HKCU` `...\CurrentVersion\Run` value names and commands (read only) |
| Collection audit | `collection_summary.json` | Which sources succeeded / were empty / errored, with reasons |

## Usage

```powershell
# On the Windows lab machine, in the repository root:
# (PowerShell "Run as Administrator")
Set-ExecutionPolicy -Scope Process Bypass
.\collectors\windows\collector.ps1 -OutputDir .\output\windows -MaxEvents 500
```

Then parse + detect (from the repository root, any machine):

```bash
python run_windows_demo.py --input output/windows
```

## Safety rules

1. Read-only `Get-*` cmdlets only — no `Clear-EventLog`, no `Set-ItemProperty`,
   no `Set-Service`, no task creation.
2. No passwords, tokens, or private keys are collected.
3. If a source is unavailable, the error is recorded in
   `collection_summary.json` — data is never fabricated.
4. The script writes only into `-OutputDir` and the summary file.
5. Do **not** commit real collected evidence to GitHub. Keep it under
   `output/` (already in `.gitignore`). Commit only sanitized samples in
   `sample_data/windows/`.

## Lab test (repeatable) — record result as `WINDOWS-COLLECT-TEST-001`

1. Create a harmless temporary scheduled task that only writes a timestamp:
   ```powershell
   schtasks /create /tn "DFIR-Test-Artifact" /tr "cmd /c echo %DATE% %TIME% > %TEMP%\dfir_test.txt" /sc once /st 23:59
   ```
2. Generate 3-5 harmless failed logons (wrong password) for a test account,
   for example using `runas /user:LAB\testaccount cmd` and typing a wrong
   password. Note the times.
3. Run the collector (see Usage above).
4. Verify: `security_events.jsonl` contains the `4625` events with correct
   UTC timestamps and record IDs; `scheduled_tasks.json` contains
   `DFIR-Test-Artifact`.
5. Clean up:
   ```powershell
   schtasks /delete /tn "DFIR-Test-Artifact" /f
   Remove-Item "$env:TEMP\dfir_test.txt" -ErrorAction SilentlyContinue
   ```
6. Record in the test log: Test ID, host, UTC time, expected vs actual result.

## Known limitations

- Security event *message* field is truncated to the first line (full
  details stay available in the raw event XML via record ID).
- Registry Run keys are read from the standard `Run` locations only
  (no `RunOnce`, no `Wow6432Node` yet).
- Sysmon events are not collected yet (planned, if Sysmon is installed
  in the lab).
- The script reads the local machine only; no remote collection.
