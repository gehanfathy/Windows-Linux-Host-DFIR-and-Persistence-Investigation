"""Tests for collectors/windows: sample data presence, raw format,
read-only collector script, and absence of secrets (team guide 03)."""

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SAMPLES = REPO / "sample_data" / "windows"


def test_sample_files_exist():
    expected = [
        "security_events_sample.jsonl",
        "scheduled_tasks_sample.json",
        "services_sample.json",
        "registry_runkeys_sample.json",
    ]
    for name in expected:
        assert (SAMPLES / name).exists(), f"missing sample file: {name}"


def test_security_sample_has_all_required_event_ids_and_fields():
    lines = [
        line for line in
        (SAMPLES / "security_events_sample.jsonl")
        .read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    events = [json.loads(line) for line in lines]

    event_ids = {event["event_id"] for event in events}
    assert {4624, 4625, 4720, 4732, 1102} <= event_ids, (
        "sample must contain 4624, 4625, 4720, 4732 and 1102")

    for event in events:
        for key in ("collection_type", "host_id", "event_id", "record_id",
                    "timestamp", "provider", "message", "data"):
            assert key in event, f"missing raw field '{key}'"
        assert event["timestamp"].endswith("Z"), "timestamps must be UTC"
        assert isinstance(event["data"], dict)


def test_item_samples_have_collection_type_and_items():
    for name, ctype in [
        ("scheduled_tasks_sample.json", "windows_scheduled_tasks"),
        ("services_sample.json", "windows_services"),
        ("registry_runkeys_sample.json", "windows_registry_runkeys"),
    ]:
        doc = json.loads((SAMPLES / name).read_text(encoding="utf-8"))
        assert doc["collection_type"] == ctype, name
        assert isinstance(doc["items"], list) and doc["items"], name
        assert doc["host_id"], name


def test_no_secrets_in_sample_data():
    for path in SAMPLES.iterdir():
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        assert "password=" not in text, path.name
        assert "private key" not in text, path.name
        assert "bearer " not in text, path.name


def test_collector_script_is_read_only():
    script = REPO / "collectors" / "windows" / "collector.ps1"
    assert script.exists(), "collector.ps1 missing"
    content = script.read_text(encoding="utf-8-sig")

    assert "Get-WinEvent" in content
    assert "Get-ScheduledTask" in content
    assert "Get-CimInstance" in content
    assert "Get-ItemProperty" in content

    forbidden = ("Clear-EventLog", "Set-ItemProperty", "Set-Service",
                 "Stop-Service", "Register-ScheduledTask",
                 "schtasks /create", "Remove-Item")
    for cmd in forbidden:
        assert cmd not in content, (
            f"collector must stay read-only but contains '{cmd}'")
