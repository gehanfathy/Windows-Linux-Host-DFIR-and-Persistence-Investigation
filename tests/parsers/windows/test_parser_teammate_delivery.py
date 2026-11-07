"""Compatibility tests — Windows-Collector delivery format.

The Windows-collector owner delivered a collector whose output uses
singular/short collection_type values and flat field names
(deliveries/windows-collector/). The parser must accept BOTH that format
and the canonical docs/DATA_CONTRACT.md format, so evidence from either
collector flows through the pipeline unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# 1. The sanitized delivery sample (real file shipped in the repo)
# ---------------------------------------------------------------------------

def test_sanitized_delivery_sample_parses() -> None:
    from parsers.windows.parser import parse_directory

    events, warnings = parse_directory(
        REPO / "sample_data" / "sanitized", "case-delivery-001"
    )

    # The sample holds one 4624 + one 4625 security event.
    assert len(events) == 2
    assert warnings == []
    assert {e["event_type"] for e in events} == {"successful_login", "failed_login"}
    for event in events:
        assert event["platform"] == "windows"
        assert event["host_id"] == "WIN-LAB-SAMPLE"
        assert event["timestamp"].endswith("Z")


def test_delivery_ip_address_alias_reaches_metadata() -> None:
    """data.ip_address (delivery name) must land in metadata.source_ip —
    the brute-force rules key on source_ip, so losing it would silence
    WIN-AUTH-001/002."""
    from parsers.windows.parser import parse_directory

    events, _ = parse_directory(
        REPO / "sample_data" / "sanitized", "case-delivery-002"
    )
    by_type = {e["event_type"]: e for e in events}

    failed = by_type["failed_login"]
    assert failed["metadata"]["source_ip"] == "192.0.2.20"
    assert failed["metadata"]["username"] == "SAMPLE_USER"
    assert failed["metadata"]["original_event_id"] == 4625
    assert failed["evidence_reference"] == "security.evtx:record-1002"

    success = by_type["successful_login"]
    assert success["metadata"]["source_ip"] == "192.0.2.10"


# ---------------------------------------------------------------------------
# 2. The delivery's flat task / service / registry output format
#    (mirrors exactly what the delivered collector.ps1 writes)
# ---------------------------------------------------------------------------

def _delivery_style_dir(tmp_path: Path) -> Path:
    records = {
        "scheduled_tasks.jsonl": {
            "collection_type": "windows_scheduled_task",
            "host_id": "HOST-X",
            "timestamp": "2026-11-05T12:00:00Z",
            "task_name": "SystemHealthUpdater",
            "task_path": "\\",
            "author": "tester",
            "action_type": "MSFT_TaskExecAction",
            "executable_path": "C:\\Windows\\Temp\\svchost32.exe",
            "arguments": "-q",
            "working_directory": None,
            "com_class_id": None,
            "com_data": None,
            "run_as_user": "SYSTEM",
            "logon_type": "S4U",
            "run_level": "Highest",
        },
        "services.jsonl": {
            "collection_type": "windows_service",
            "host_id": "HOST-X",
            "timestamp": "2026-11-05T12:00:00Z",
            "name": "UpdateHelper",
            "display_name": "Update Helper",
            "status": "Running",
            "start_type": "Auto",
            "binary_path": "C:\\Users\\Public\\updater.exe",
            "account": "LocalSystem",
        },
        "registry_run_keys.jsonl": {
            "collection_type": "windows_registry_run",
            "host_id": "HOST-X",
            "timestamp": "2026-11-05T12:00:00Z",
            "registry_path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "SysTray",
            "value_data": "C:\\Users\\labuser\\AppData\\Roaming\\systray.exe",
        },
    }
    for file_name, record in records.items():
        (tmp_path / file_name).write_text(
            json.dumps(record) + "\n", encoding="utf-8"
        )
    return tmp_path


def test_delivery_flat_formats_parse(tmp_path: Path) -> None:
    from parsers.windows.parser import parse_directory

    events, warnings = parse_directory(_delivery_style_dir(tmp_path), "case-flat-001")

    assert warnings == []
    assert len(events) == 3
    # File order is stable: scheduled -> service -> registry.
    task, service, runkey = events

    assert task["event_type"] == "scheduled_task_created"
    assert task["metadata"]["task_name"] == "SystemHealthUpdater"
    assert task["metadata"]["action_execute"] == "C:\\Windows\\Temp\\svchost32.exe"
    assert task["metadata"]["run_as"] == "SYSTEM"

    assert service["event_type"] == "service_created"
    assert service["metadata"]["binary_path"] == "C:\\Users\\Public\\updater.exe"

    assert runkey["event_type"] == "persistence_detected"
    assert runkey["metadata"]["hive"] == "HKCU"
    assert runkey["metadata"]["key"] == (
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    assert runkey["metadata"]["command"] == (
        "C:\\Users\\labuser\\AppData\\Roaming\\systray.exe"
    )


def test_delivery_flat_format_fires_detection(tmp_path: Path) -> None:
    """The suspicious delivery-style records must reach the persistence
    rules (same WIN-PERS findings as the canonical samples)."""
    from detection.windows.rules import run_detection
    from parsers.windows.parser import parse_directory

    events, warnings = parse_directory(_delivery_style_dir(tmp_path), "case-flat-002")
    assert warnings == []

    findings, _iocs = run_detection(events, "case-flat-002")
    rule_ids = {f["rule_id"] for f in findings}
    assert "WIN-PERS-001" in rule_ids  # task in C:\Windows\Temp
    assert "WIN-PERS-002" in rule_ids  # run key in AppData\Roaming
    assert "WIN-PERS-003" in rule_ids  # service in C:\Users\Public
    for finding in findings:
        assert finding["status"] == "unverified"


# ---------------------------------------------------------------------------
# 3. Metadata-only delivery records (PowerShell / Sysmon)
# ---------------------------------------------------------------------------

def test_metadata_only_types_are_skipped_cleanly(tmp_path: Path) -> None:
    from parsers.windows.parser import parse_directory

    record = {
        "collection_type": "windows_powershell_event",
        "host_id": "HOST-X",
        "event_id": 4104,
        "record_id": 7,
        "timestamp": "2026-11-05T12:00:00Z",
        "provider": "Microsoft-Windows-PowerShell",
        "level": "Information",
    }
    (tmp_path / "powershell_operational.jsonl").write_text(
        json.dumps(record) + "\n", encoding="utf-8"
    )

    events, warnings = parse_directory(tmp_path, "case-meta-001")

    assert events == []  # nothing inventable from metadata-only records
    assert len(warnings) == 1
    assert "metadata-only" in warnings[0]


def test_mixed_directory_canonical_and_delivery(tmp_path: Path) -> None:
    """Canonical JSON object file + delivery JSONL in the same folder."""
    from parsers.windows.parser import parse_directory

    canonical = {
        "collection_type": "windows_services",
        "host_id": "HOST-CANON",
        "collected_at": "2026-11-05T12:00:00Z",
        "items": [
            {
                "name": "LenovoVantage",
                "display_name": "Lenovo Vantage Service",
                "status": "Running",
                "start_type": "Auto",
                "binary_path": "C:\\Program Files\\Lenovo\\LenovoVantage.exe",
                "account": "LocalSystem",
            }
        ],
    }
    (tmp_path / "services.json").write_text(
        json.dumps(canonical), encoding="utf-8"
    )
    delivery = {
        "collection_type": "windows_service",
        "host_id": "HOST-X",
        "timestamp": "2026-11-05T12:00:00Z",
        "name": "UpdateHelper",
        "display_name": "Update Helper",
        "status": "Stopped",
        "start_type": "Auto",
        "binary_path": "C:\\Users\\Public\\updater.exe",
        "account": "LocalSystem",
    }
    (tmp_path / "services_delivery.jsonl").write_text(
        json.dumps(delivery) + "\n", encoding="utf-8"
    )

    events, warnings = parse_directory(tmp_path, "case-mixed-001")
    assert warnings == []
    assert len(events) == 2
    assert {e["metadata"]["service_name"] for e in events} == {
        "LenovoVantage",
        "UpdateHelper",
    }
