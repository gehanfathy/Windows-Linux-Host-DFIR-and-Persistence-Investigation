"""Tests for parsers/linux/parser.py: contract compliance, error handling,
and robustness against bad input (team guides 01/04)."""

import json
from pathlib import Path

import pytest

from parsers.linux import parser as lp

SAMPLES = Path("sample_data/linux")

REQUIRED_EVENT_FIELDS = (
    "event_id", "case_id", "host_id", "platform", "event_type",
    "timestamp", "severity", "source", "evidence_reference", "message",
    "metadata",
)

# Contract vocabulary (docs/DATA_CONTRACT.md section 3) plus the documented
# Linux additions (session_opened, sudo_command, auth_event, system_log,
# service_metadata, ssh_config_event).
ALLOWED_EVENT_TYPES = {
    "failed_login", "successful_login", "account_created", "account_modified",
    "persistence_detected", "process_execution", "network_connection",
    "file_modified", "service_created", "scheduled_task_created",
    "cron_modified", "ssh_key_modified", "audit_log_cleared",
    "session_opened", "sudo_command", "auth_event", "system_log",
    "service_metadata", "ssh_config_event",
}


@pytest.fixture(scope="module")
def parsed():
    return lp.parse_directory(SAMPLES, case_id="case-000001")


def test_sample_directory_produces_all_events(parsed):
    events, warnings = parsed
    # 12 auth + 6 syslog + 4 cron + 4 systemd + 4 ssh = 30
    assert len(events) == 30
    # Only one expected skip: the /etc/crontab header comment line.
    assert len(warnings) == 1
    assert "cron comment" in warnings[0]


def test_every_event_matches_data_contract(parsed):
    events, _ = parsed
    for event in events:
        for field in REQUIRED_EVENT_FIELDS:
            assert field in event, f"event {event.get('event_id')} missing {field}"
        assert event["platform"] == "linux"
        assert event["case_id"] == "case-000001"
        assert event["host_id"] == "LINUX-LAB-01"
        assert event["severity"] in {"low", "medium", "high", "critical"}
        assert event["event_type"] in ALLOWED_EVENT_TYPES
        assert event["timestamp"].endswith("Z"), "must be UTC ISO 8601"
        assert event["evidence_reference"], "evidence_reference required"
        assert ":line-" in event["evidence_reference"]
        assert isinstance(event["metadata"], dict)


def test_event_ids_are_sequential_and_unique(parsed):
    events, _ = parsed
    ids = [event["event_id"] for event in events]
    assert len(set(ids)) == len(ids)
    assert ids[0] == "evt-lin-000001"
    assert ids[-1] == "evt-lin-000030"


def test_event_type_mapping(parsed):
    events, _ = parsed
    types = {event["event_type"] for event in events}
    assert {
        "failed_login", "successful_login", "account_created",
        "account_modified", "audit_log_cleared", "session_opened",
        "system_log", "process_execution", "cron_modified",
        "service_metadata", "ssh_config_event", "ssh_key_modified",
    } <= types


def test_failed_login_keeps_source_ip_in_metadata(parsed):
    events, _ = parsed
    failed = [e for e in events if e["event_type"] == "failed_login"]
    assert len(failed) == 5, "sample contains 5 failed ssh passwords"
    for event in failed:
        assert event["metadata"]["source_ip"] == "203.0.113.55"
        assert event["severity"] == "medium"
        assert event["evidence_reference"].startswith("/var/log/auth.log:line-")
    assert any(e["metadata"]["invalid_user"] for e in failed)
    assert any(e["metadata"]["username"] == "root" for e in failed)


def test_successful_login_keeps_auth_method(parsed):
    events, _ = parsed
    accepted = [e for e in events if e["event_type"] == "successful_login"]
    assert len(accepted) == 2
    assert all(e["metadata"]["source_ip"] == "203.0.113.55" for e in accepted)
    assert {e["metadata"]["username"] for e in accepted} == {
        "labuser", "svc_update"}


def test_syslog_timestamp_uses_line_date_and_collected_year(parsed):
    events, _ = parsed
    first_failed = next(
        e for e in events if e["event_type"] == "failed_login")
    # Log line says "Nov  4 10:14:55"; year comes from collected_at (2026).
    assert first_failed["timestamp"] == "2026-11-04T10:14:55Z"


def test_snapshot_sources_use_collected_at(parsed):
    events, _ = parsed
    cron = [e for e in events if e["event_type"] == "cron_modified"]
    ssh = [e for e in events if e["event_type"] == "ssh_config_event"]
    assert all(e["timestamp"] == "2026-11-04T10:30:00Z" for e in cron)
    assert all(e["timestamp"] == "2026-11-04T10:30:00Z" for e in ssh)


def test_cron_user_extraction(parsed):
    events, _ = parsed
    cron = [e for e in events if e["event_type"] == "cron_modified"]
    by_command = {e["metadata"]["command"]: e for e in cron}

    # System cron file: user field is present in the line.
    update = by_command["/tmp/system_update.sh"]
    assert update["metadata"]["user"] == "root"
    assert update["metadata"]["cron_file"] == "/etc/cron.d/system-update"
    # User crontab: no user field; the user comes from the spool file name.
    report = by_command["/home/labuser/bin/report.sh"]
    assert report["metadata"]["user"] == "labuser"
    assert report["metadata"]["cron_file"] == "/var/spool/cron/crontabs/labuser"
    # /etc/crontab rule with a user field.
    hourly = [e for e in cron if "run-parts" in e["metadata"]["command"]][0]
    assert hourly["metadata"]["user"] == "root"


def test_sudo_account_lifecycle_mapping(parsed):
    events, _ = parsed
    created = [e for e in events if e["event_type"] == "account_created"]
    assert len(created) == 2  # sudo useradd + useradd daemon log
    for event in created:
        assert event["severity"] == "high"
        assert event["metadata"].get("target_account") == "svc_update" or \
            event["metadata"].get("username") == "svc_update"
    modified = [e for e in events if e["event_type"] == "account_modified"]
    assert len(modified) == 1
    assert modified[0]["metadata"]["target_account"] == "svc_update"
    assert "sudo" in modified[0]["metadata"]["command"]


def test_journalctl_vacuum_maps_to_audit_log_cleared(parsed):
    events, _ = parsed
    cleared = [e for e in events if e["event_type"] == "audit_log_cleared"]
    assert len(cleared) == 1
    assert "journalctl" in cleared[0]["metadata"]["command"]
    assert cleared[0]["severity"] == "high"


def test_ssh_authorized_key_parsed(parsed):
    events, _ = parsed
    keys = [e for e in events if e["event_type"] == "ssh_key_modified"]
    assert len(keys) == 1
    event = keys[0]
    assert event["metadata"]["key_type"] == "ssh-ed25519"
    assert event["metadata"]["ssh_file"] == \
        "/home/labuser/.ssh/authorized_keys"
    assert event["metadata"]["comment"] == "labuser@lab-laptop"
    # The key material recorded is PUBLIC key material, not a secret.
    assert event["metadata"]["key_data"].startswith("AAAAC3NzaC1lZDI1NTE5")


def test_private_key_material_is_never_collected(parsed):
    events, _ = parsed
    for event in events:
        blob = json.dumps(event)
        assert "PRIVATE KEY" not in blob
        assert "BEGIN RSA" not in blob


def test_collection_summary_file_is_skipped(tmp_path):
    summary = {
        "tool": "linux-collector", "host_id": "LINUX-LAB-01",
        "totals": {"records": 4},
    }
    (tmp_path / "collection_summary.json").write_text(
        json.dumps(summary), encoding="utf-8")
    events, warnings = lp.parse_file(
        tmp_path / "collection_summary.json", case_id="case-000001")
    assert events == []
    assert any("summary" in warning for warning in warnings)


def test_missing_directory_is_a_warning_not_crash(tmp_path):
    events, warnings = lp.parse_directory(tmp_path / "does-not-exist")
    assert events == []
    assert any("not found" in warning for warning in warnings)


def test_invalid_json_is_a_warning_not_crash(tmp_path):
    (tmp_path / "broken.json").write_text("{not valid json", encoding="utf-8")
    events, warnings = lp.parse_directory(tmp_path)
    assert events == []
    assert any("invalid JSON" in warning for warning in warnings)


def test_missing_source_status_is_reported(tmp_path):
    payload = {
        "collection_type": "linux_auth_log",
        "host_id": "LINUX-LAB-01",
        "collected_at": "2026-11-04T10:30:00Z",
        "status": "missing",
        "records": [],
    }
    (tmp_path / "auth_log.json").write_text(
        json.dumps(payload), encoding="utf-8")
    events, warnings = lp.parse_directory(tmp_path)
    assert events == []
    assert any("status 'missing'" in warning for warning in warnings)


def test_missing_host_id_is_rejected(tmp_path):
    payload = {
        "collection_type": "linux_auth_log",
        "collected_at": "2026-11-04T10:30:00Z",
        "status": "collected",
        "records": [
            {"line_no": 1, "source": "/var/log/auth.log",
             "message": "Nov  4 10:14:55 h sshd[1]: Accepted password for u "
                        "from 1.2.3.4 port 1 ssh2"},
        ],
    }
    (tmp_path / "auth_log.json").write_text(
        json.dumps(payload), encoding="utf-8")
    events, warnings = lp.parse_directory(tmp_path)
    assert events == []
    assert any("missing host_id" in warning for warning in warnings)


def test_unrecognized_cron_line_is_skipped(tmp_path):
    payload = {
        "collection_type": "linux_cron",
        "host_id": "LINUX-LAB-01",
        "collected_at": "2026-11-04T10:30:00Z",
        "status": "collected",
        "records": [
            {"line_no": 1, "source": "/etc/crontab",
             "message": "MAILTO=admin@example.com"},
            {"line_no": 2, "source": "/etc/crontab",
             "message": "0 2 * * * root /opt/scripts/backup.sh"},
        ],
    }
    (tmp_path / "cron.json").write_text(json.dumps(payload), encoding="utf-8")
    events, warnings = lp.parse_directory(tmp_path)
    assert len(events) == 1
    assert len(warnings) == 1
    assert events[0]["metadata"]["command"] == "/opt/scripts/backup.sh"


def test_naive_collected_at_is_rejected(tmp_path):
    payload = {
        "collection_type": "linux_auth_log",
        "host_id": "LINUX-LAB-01",
        "collected_at": "2026-11-04T10:30:00",  # no timezone -> contract break
        "status": "collected",
        "records": [
            {"line_no": 1, "source": "/var/log/auth.log",
             "message": "some auth line without syslog date"},
        ],
    }
    (tmp_path / "auth_log.json").write_text(
        json.dumps(payload), encoding="utf-8")
    events, warnings = lp.parse_directory(tmp_path)
    assert events == []
    assert any("no timestamp available" in warning for warning in warnings)
