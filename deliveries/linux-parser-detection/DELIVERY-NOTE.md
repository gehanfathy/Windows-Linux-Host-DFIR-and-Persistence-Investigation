# Linux Parser & Detection — Original Delivery (v1)

This folder preserves the **original delivery** from the team member owning
the Linux parser & detection task (submitted as `DFIR-Project-main.zip`,
a `main` branch archive of the teammate's repository).

| Item | What it is |
|---|---|
| `core/` | Teammate's own `NormalizedEvent` / `NormalizedFinding` dataclasses (kept as delivered). |
| `parsers/linux/` | Parsers for `auth.log`, `crontab`, `authorized_keys`, systemd services. |
| `detection/linux/` | Rules `LINUX-AUTH-001`, `LINUX-CRON-001`, `LINUX-SSH-001`. |
| `samples/linux/` | The teammate's own sample artifacts (auth logs, crontab, keys, services). |
| `test_auth.py`, `test_cron.py`, `test_ssh.py`, `test_systemd.py`, `tests/` | The teammate's own test suite (kept unchanged). |
| `README.md` | The module owner's usage instructions (kept unchanged). |
| `DELIVERY-NOTE.md` | This file — the team leader's review and integration record. |

## Leader review (integration phase, task 04)

**Verdict: accepted as a delivery and preserved verbatim.** The module works,
is well tested, and handles malformed input safely. It is **not wired into the
canonical pipeline yet** — see the compatibility section below.

Review performed on the delivered archive:

| Check | Result |
|---|---|
| Teammate's test suite | **28 / 28 passed** (`pytest`, 0.12 s) |
| `auth.log` sample | 4 events (failed_login, successful_login, invalid_user, sudo_activity) |
| `auth_bruteforce.log` sample | 3 events → `LINUX-AUTH-001` fires **1 finding** (medium / unverified) |
| `auth_outside_window.log` sample | 3 events → **0 findings** (time window correctly respected) |
| `crontab` sample | 4 events → 0 findings on this sample (rule covered by unit tests) |
| `authorized_keys` sample | 2 events |
| `systemd_services.txt` sample | 3 events |

### Strengths

- Sliding-window brute force detection per source IP, with overlapping-window
  de-duplication.
- Accepts both ISO timestamps and classic syslog timestamps, normalizes to UTC.
- Garbage / unknown lines are skipped without crashing.
- Evidence references are preserved end to end (`auth.log:line-N`).
- Finding IDs are namespaced by rule (`LINUX-AUTH-001-0001`), which avoids the
  cross-platform ID collisions a shared `finding-000001`-style counter can
  produce. This is a good convention to adopt in the canonical rules later.

## Compatibility with the canonical schema (`app/models/schemas.py`)

The delivery is **close to, but not drop-in compatible with**, the canonical
project schema. Gaps that the integration adapter must handle:

| # | Delivery behaviour | Canonical requirement |
|---|---|---|
| 1 | `timestamp` is a syslog string (`"Nov  4 10:15:00"`) or `None` | ISO `datetime` (required) |
| 2 | `severity` may be `"info"` (sudo events) | one of `low / medium / high / critical` |
| 3 | Finding has no `case_id`, `host_id`, `platform`, no `title`/`description` (uses `message`), no `mitre_technique`, no `related_evidence` | all required by `NormalizedFinding` |
| 4 | `event_id` scheme `LINUX-AUTH-<line>`; `case_id` default `"CASE-001"` | canonical schemes `evt-linux-…` / `case-000001` (parameterizable) |

These gaps are pinned by
[`tests/integration/test_teammate_linux_delivery.py`](../../tests/integration/test_teammate_linux_delivery.py)
so that any change on either side is caught during integration.

## Why this is kept separately

The canonical Linux pipeline
([`parsers/linux/parser.py`](../../parsers/linux/parser.py) +
[`detection/linux/rules.py`](../../detection/linux/rules.py)) already covers
`auth.log`, syslog, systemd units, cron and SSH metadata end to end and feeds
the FastAPI/SQLite app. To keep history and provenance clean:

- the canonical pipeline stays the single source of truth for the dashboard;
- this delivery is preserved **as submitted** for review, grading and traceability;
- an adapter (timestamp normalization, severity mapping `info → low`, finding
  field mapping) will be added in a later integration step if the team decides
  to merge these rules into the canonical rule set.

This mirrors the existing pattern used for
[`deliveries/windows-collector/`](../windows-collector/DELIVERY-NOTE.md).

## Running the delivery's own tests

From the repository root, run them **from inside this folder with explicit
file arguments** (the root `pytest.ini` intentionally skips `deliveries/`):

```
cd deliveries/linux-parser-detection
python -m pytest test_auth.py test_cron.py test_ssh.py test_systemd.py tests -q
```

The delivery's tests use relative sample paths, so they must be started from
this folder.
