"""Tests for detection/windows/rules.py: rule triggering, evidence
references, contract compliance, and no false positives on clean data."""

import json
from pathlib import Path

import pytest

from app.models.schemas import NormalizedFinding, NormalizedIOC
from detection.windows import rules
from parsers.windows import parser as wp

SAMPLES = Path("sample_data/windows")

ALLOWED_IOC_TYPES = {
    "ip_address", "domain", "file_path", "file_hash", "username", "email",
    "registry_key", "scheduled_task", "service_name", "ssh_key",
}


@pytest.fixture(scope="module")
def sample_events():
    return wp.parse_directory(SAMPLES, case_id="case-000001")[0]


def _make_failed_login(ip, timestamp, username="labadmin", record=1):
    return {
        "event_id": f"evt-win-{record:06d}",
        "case_id": "case-000001",
        "host_id": "WIN-LAB-01",
        "platform": "windows",
        "event_type": "failed_login",
        "timestamp": timestamp,
        "severity": "medium",
        "source": "security.evtx",
        "evidence_reference": f"security.evtx:record-{record}",
        "message": "Failed logon",
        "metadata": {"username": username, "source_ip": ip,
                     "original_event_id": 4625},
    }


def _make_task_event(name, execute, record=1):
    return {
        "event_id": f"evt-win-{record:06d}",
        "case_id": "case-000001",
        "host_id": "WIN-LAB-01",
        "platform": "windows",
        "event_type": "scheduled_task_created",
        "timestamp": "2026-11-05T10:00:00Z",
        "severity": "low",
        "source": "Scheduled Tasks",
        "evidence_reference": f"Tasks\\{name}",
        "message": f"Scheduled task '{name}'",
        "metadata": {"task_name": name, "action_execute": execute,
                     "run_as": "SYSTEM"},
    }


def test_sample_produces_all_five_rules(sample_events):
    findings, _ = rules.run_detection(sample_events)
    rule_ids = {f["rule_id"] for f in findings}
    assert {"WIN-AUTH-001", "WIN-AUTH-002",
            "WIN-PERS-001", "WIN-PERS-002", "WIN-PERS-003"} <= rule_ids


def test_findings_are_unverified_with_evidence(sample_events):
    findings, iocs = rules.run_detection(sample_events)
    assert findings and iocs
    for finding in findings:
        assert finding["status"] == "unverified"
        assert finding["evidence_reference"]
        assert finding["rule_id"].startswith("WIN-")
        assert finding["platform"] == "windows"


def test_findings_and_iocs_validate_against_schemas(sample_events):
    findings, iocs = rules.run_detection(sample_events)
    for finding in findings:
        NormalizedFinding.model_validate(finding)
    for ioc in iocs:
        NormalizedIOC.model_validate(ioc)
        assert ioc["ioc_type"] in ALLOWED_IOC_TYPES


def test_brute_force_detected_with_burst_evidence():
    events = [
        _make_failed_login("10.0.0.55", "2026-11-05T09:10:01Z", record=1),
        _make_failed_login("10.0.0.55", "2026-11-05T09:10:31Z", record=2),
        _make_failed_login("10.0.0.55", "2026-11-05T09:11:02Z", record=3),
    ]
    findings, iocs = rules.run_detection(events)
    bf = [f for f in findings if f["rule_id"] == "WIN-AUTH-001"]
    assert len(bf) == 1
    assert bf[0]["severity"] == "medium"
    assert len(bf[0]["related_evidence"]) == 3
    assert any(ioc["ioc_type"] == "ip_address" and ioc["value"] == "10.0.0.55"
               for ioc in iocs)


def test_two_scattered_failures_do_not_trigger_brute_force():
    events = [
        _make_failed_login("10.0.0.55", "2026-11-05T09:10:01Z", record=1),
        _make_failed_login("10.0.0.55", "2026-11-05T09:55:01Z", record=2),
    ]
    findings, _ = rules.run_detection(events)
    assert not [f for f in findings if f["rule_id"] == "WIN-AUTH-001"]


def test_success_after_failures_triggers_win_auth_002():
    events = [
        _make_failed_login("10.0.0.55", "2026-11-05T09:10:01Z", record=1),
        _make_failed_login("10.0.0.55", "2026-11-05T09:10:31Z", record=2),
        {
            "event_id": "evt-win-000003",
            "case_id": "case-000001",
            "host_id": "WIN-LAB-01",
            "platform": "windows",
            "event_type": "successful_login",
            "timestamp": "2026-11-05T09:13:20Z",
            "severity": "low",
            "source": "security.evtx",
            "evidence_reference": "security.evtx:record-3",
            "message": "Successful logon",
            "metadata": {"username": "helpdesk", "source_ip": "10.0.0.55"},
        },
    ]
    findings, _ = rules.run_detection(events)
    hits = [f for f in findings if f["rule_id"] == "WIN-AUTH-002"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "high"


def test_clean_task_from_program_files_is_not_flagged():
    events = [_make_task_event("LegitTask",
                               "C:\\Program Files\\Vendor\\tool.exe")]
    findings, _ = rules.run_detection(events)
    assert findings == []


def test_suspicious_task_from_temp_is_flagged():
    events = [_make_task_event("SystemHealthUpdater",
                               "C:\\Windows\\Temp\\svchost32.exe")]
    findings, iocs = rules.run_detection(events)
    assert [f["rule_id"] for f in findings] == ["WIN-PERS-001"]
    values = {(ioc["ioc_type"], ioc["value"]) for ioc in iocs}
    assert ("scheduled_task", "SystemHealthUpdater") in values
    assert ("file_path", "C:\\Windows\\Temp\\svchost32.exe") in values


def test_empty_input_returns_empty_results():
    findings, iocs = rules.run_detection([])
    assert findings == [] and iocs == []
