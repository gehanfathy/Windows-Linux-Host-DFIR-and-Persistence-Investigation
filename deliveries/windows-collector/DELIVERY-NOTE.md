# Windows Collector — Original Delivery (v1)

This folder preserves the **original delivery** from the team member owning
the Windows collector task (submitted as `Windows-Collector-Delivery.zip`).

| File | What it is |
|---|---|
| `collector.ps1` | The collector as first delivered: Security events **4624/4625**, scheduled tasks, services, registry Run keys, plus metadata-only PowerShell Operational and Sysmon logs. Read-only. |
| `README.md` | The collector owner's own usage instructions (kept unchanged). |

## Why this is kept separately

The canonical collector used by the pipeline is
[`collectors/windows/collector.ps1`](../../collectors/windows/collector.ps1),
which additionally covers event IDs **4720 / 4732 / 1102** and writes the
canonical `collection_type` values from `docs/DATA_CONTRACT.md`.

The parser (`parsers/windows/parser.py`) accepts **both output formats**, so
evidence produced by either collector works end to end:

| Source | Canonical type | Delivery alias (also accepted) |
|---|---|---|
| Security events | `windows_security_event` | — (identical; `data.ip_address` is accepted as an alias of `data.source_ip`) |
| Scheduled tasks | `windows_scheduled_tasks` | `windows_scheduled_task` |
| Services | `windows_services` | `windows_service` |
| Registry Run keys | `windows_registry_runkeys` | `windows_registry_run`, `windows_registry_run_key` |
| PowerShell / Sysmon | — | metadata-only records are skipped with a warning |

Sanitized sample output from this delivery lives in
[`sample_data/sanitized/`](../../sample_data/sanitized/) together with the
supported-sources document, and is covered by
`tests/parsers/windows/test_parser_teammate_delivery.py`.
