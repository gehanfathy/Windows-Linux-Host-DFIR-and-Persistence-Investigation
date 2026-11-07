"""Tests for parsers/windows/parser.py: contract compliance, error
handling, and robustness against bad input (team guide 02/03)."""

import json
from pathlib import Path

import pytest

from parsers.windows import parser as wp

SAMPLES = Path("sample_data/windows")

REQUIRED_EVENT_FIELDS = (
    "event_id", "case_id", "host_id", "platform", "event_type",
    "timestamp", "severity", "source", "evidence_reference", "message",
    "metadata",
)

ALLOWED_EVENT_TYPES = {
    "failed_login", "successful_login", "account_created", "account_modified",
    "persistence_detected", "process_execution", "network_connection",
    "file_modified", "service_created", "scheduled_task_created",
    "cron_modified", "ssh_key_modified", "audit_log_cleared",
}


@pytest.fixture(scope="module")
def parsed():
    return wp.parse_directory(SAMPLES, case_id="case-000001")


def test_sample_directory_produces_all_events(parsed):
    events, warnings = parsed
    # 11 security events + 3 tasks + 3 services + 3 run keys = 20
    assert len(events) == 20
    assert warnings == []


def test_every_event_matches_data_contract(parsed):
    events, _ = parsed
    for event in events:
        for field in REQUIRED_EVENT_FIELDS:
            assert field in event, f"event {event.get('event_id')} missing {field}"
        assert event["platform"] == "windows"
        assert event["severity"] in {"low", "medium", "high", "critical"}
        assert event["event_type"] in ALLOWED_EVENT_TYPES
        assert event["timestamp"].endswith("Z"), "must be UTC ISO 8601"
        assert event["evidence_reference"], "evidence_reference required"
        assert isinstance(event["metadata"], dict)


def test_event_ids_are_sequential_and_unique(parsed):
    events, _ = parsed
    ids = [event["event_id"] for event in events]
    assert len(set(ids)) == len(ids)
    assert ids[0] == "evt-win-000001"
    assert ids[-1] == "evt-win-000020"


def test_event_type_mapping(parsed):
    events, _ = parsed
    types = {event["event_type"] for event in events}
    assert {"failed_login", "successful_login", "account_created",
            "account_modified", "audit_log_cleared", "scheduled_task_created",
            "service_created", "persistence_detected"} <= types


def test_failed_login_keeps_source_ip_in_metadata(parsed):
    events, _ = parsed
    failed = [e for e in events if e["event_type"] == "failed_login"]
    assert failed, "sample contains 4625 events"
    for event in failed:
        assert event["metadata"]["source_ip"] == "10.0.0.55"
        assert event["evidence_reference"].startswith("security.evtx:record-")


def test_unparsable_lines_are_skipped_without_crash(tmp_path):
    good = json.dumps({
        "collection_type": "windows_security_event",
        "host_id": "WIN-LAB-01",
        "event_id": 4625,
        "record_id": 1,
        "timestamp": "2026-11-05T09:10:01Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "message": "An account failed to log on",
        "data": {"target_username": "labadmin", "source_ip": "10.0.0.55"},
    })
    bad_file = tmp_path / "security_events.jsonl"
    bad_file.write_text(
        good + "\nthis is not json\n{\"broken\": true}\n", encoding="utf-8")

    events, warnings = wp.parse_file(bad_file, case_id="case-000001")
    assert len(events) == 1
    assert len(warnings) == 2  # invalid JSON + missing required fields


def test_missing_input_directory_does_not_crash(tmp_path):
    events, warnings = wp.parse_directory(tmp_path / "does-not-exist")
    assert events == []
    assert warnings, "a warning must be recorded for the missing directory"


def test_naive_timestamp_is_rejected(tmp_path):
    line = json.dumps({
        "collection_type": "windows_security_event",
        "host_id": "WIN-LAB-01",
        "event_id": 4625,
        "record_id": 2,
        "timestamp": "2026-11-05T09:10:01",  # no timezone info
        "provider": "x",
        "message": "An account failed to log on",
        "data": {"target_username": "labadmin"},
    })
    f = tmp_path / "security_events.jsonl"
    f.write_text(line + "\n", encoding="utf-8")

    events, warnings = wp.parse_file(f, case_id="case-000001")
    assert events == []
    assert len(warnings) == 1
    assert "timestamp" in warnings[0]
