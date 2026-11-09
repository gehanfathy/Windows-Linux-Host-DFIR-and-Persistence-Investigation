# Linux Collector — Read-Only Evidence Collection

Collects raw Linux evidence as structured JSON for the DFIR pipeline
(Task 01 — Linux Collector). The collector **never modifies the system**:
it only reads files and runs read-only `systemctl` queries.

## Requirements

- Any Linux with Python 3.9+ (no external packages — stdlib only)
- Reading `/var/log/auth.log` and user crontabs may need **sudo/root**;
  anything unreadable is recorded in the summary instead of crashing
- No external dependencies

## What it collects

| Source | Output file | Content |
|---|---|---|
| Authentication | `auth_log.json` | `/var/log/auth.log` or `/var/log/secure` — logon attempts, sudo, sshd |
| System logs | `syslog.json` | `/var/log/syslog` or `/var/log/messages` |
| Cron | `cron.json` | `/etc/crontab`, `/etc/cron.d/*`, user crontabs (if readable) |
| Systemd services | `systemd_services.json` | service names + state (`systemctl`, fallback: unit-file scan) |
| SSH metadata | `ssh_metadata.json` | `/etc/ssh/sshd_config` + `authorized_keys` (public keys only) |
| Collection audit | `collection_summary.json` | which sources succeeded / were empty / missing / errored, with reasons |

Every record carries: `line_no`, `source`, `message`. Every file carries
`host_id`, `collected_at` (UTC), `collection_type`, and `status`.

## Usage

```bash
# On the Linux lab machine, in the repository root:
python3 collectors/linux/collector.py
python3 collectors/linux/collector.py --output-dir output/linux \
    --host-id LINUX-LAB-01 --max-lines 500
```

Then (later, when the Linux parser is delivered) the raw output feeds the
parser the same way the Windows collector feeds `parsers/windows/`.

## Safety rules

1. Read-only access only — no edits, no deletions, no service changes.
2. **Private keys are never collected** (`id_rsa`, `id_ed25519`, ... are not
   in the source list), and a final safety scan drops any record containing
   a private-key marker before writing.
3. No passwords, tokens, or secrets are collected.
4. Missing or unreadable sources are recorded in `collection_summary.json`
   — data is never fabricated.
5. **Raw logs stay local**: `output/linux/` is gitignored and must never be
   pushed to GitHub. Only sanitized samples under `sample_data/linux/` go
   to GitHub.

## Lab test (repeatable) — record result as `LINUX-COLLECT-TEST-001`

1. Note the line count of the auth log before the test
   (`wc -l /var/log/auth.log`).
2. Create authorized, harmless activity: several failed logons with a
   non-sensitive lab account (e.g. `runuser -u labtest -- true` with a wrong
   setup, or failed `ssh labtest@localhost` attempts).
3. Run the collector (see Usage above).
4. Verify: `auth_log.json` contains the new records with correct line
   numbers, and `collection_summary.json` shows `auth_log: collected`.
5. Record in the test log: Test ID `LINUX-COLLECT-TEST-001`, host, UTC time,
   line counts before/after, expected vs actual result.
6. If records did not appear, the problem is in file reading or permissions
   — not in detection.

## Known limitations

- Journal-only systems (no plain-text auth.log) are not covered yet.
- Auditd logs are not collected in this first deliverable.
