"""End-to-end integration test (team guide 04):

sample_data/windows -> parser -> detection rules -> FastAPI -> SQLite.

Proves the whole chain works against the real API application."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from detection.windows import rules
from parsers.windows import parser as wp

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Fresh API + fresh SQLite database in a temporary location."""
    monkeypatch.chdir(tmp_path)  # data/dfir.db is created relative to cwd
    from app.api.main import app
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_windows_pipeline_end_to_end(client):
    events, warnings = wp.parse_directory(
        REPO / "sample_data" / "windows", case_id="case-e2e-001")
    assert events and warnings == []

    findings, iocs = rules.run_detection(events, case_id="case-e2e-001")
    # WIN-AUTH-001 + 2x WIN-AUTH-002 (helpdesk & svc_update logons from the
    # suspicious IP) + WIN-PERS-001/002/003
    assert len(findings) == 6
    assert len(iocs) >= 6

    # Push events
    for event in events:
        response = client.post("/events", json=event)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "created"

    # Push findings
    for finding in findings:
        response = client.post("/findings", json=finding)
        assert response.status_code == 200, response.text

    # Push IOCs
    for ioc in iocs:
        response = client.post("/iocs", json=ioc)
        assert response.status_code == 200, response.text

    # Read back through the API
    stored_events = client.get("/events").json()
    assert len(stored_events) == len(events)
    assert any(e["event_type"] == "failed_login" for e in stored_events)
    assert any(e["platform"] == "windows" for e in stored_events)

    stored_findings = client.get("/findings").json()
    assert {f["rule_id"] for f in stored_findings} == {
        f["rule_id"] for f in findings}
    for finding in stored_findings:
        assert finding["status"] == "unverified"
        assert finding["evidence_reference"]

    stored_iocs = client.get("/iocs").json()
    assert {i["ioc_type"] for i in stored_iocs} <= {
        "ip_address", "username", "file_path", "registry_key",
        "scheduled_task", "service_name",
    }

    # Traceability: every finding's evidence reference must exist
    # in the event evidence references we stored
    event_refs = {e["evidence_reference"] for e in stored_events}
    for finding in stored_findings:
        assert finding["evidence_reference"] in event_refs


def test_invalid_event_is_rejected_by_validation(client):
    bad_event = {
        "event_id": "evt-bad-000001",
        "case_id": "case-e2e-001",
        "host_id": "WIN-LAB-01",
        "platform": "windows",
        "event_type": "failed_login",
        "timestamp": "2026-11-05T09:10:01Z",
        "severity": "not-a-severity",  # invalid
        "source": "security.evtx",
        "evidence_reference": "security.evtx:record-1",
        "message": "bad",
        "metadata": {},
    }
    response = client.post("/events", json=bad_event)
    assert response.status_code == 422  # pydantic validation error
