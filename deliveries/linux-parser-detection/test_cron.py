from core.normalized_event import NormalizedEvent
from parsers.linux.cron_parser import parse_cron_file
from detection.linux.cron_rules import detect_suspicious_cron


def test_cron_parser_extracts_fields():
    events = parse_cron_file(
        "samples/linux/crontab",
        system_crontab=True
    )

    assert len(events) == 4

    first_event = events[0]

    assert first_event.event_type == "cron_job"
    assert first_event.metadata["schedule"] == "*/5 * * * *"
    assert first_event.metadata["user"] == "root"
    assert first_event.metadata["command"] == "/usr/bin/backup.sh"
    assert first_event.evidence_reference == "crontab:line-2"


def test_cron_detection():
    events = parse_cron_file(
        "samples/linux/crontab",
        system_crontab=True
    )

    findings = detect_suspicious_cron(events)

    assert len(findings) == 2

    assert all(
        finding.rule_id == "LINUX-CRON-001"
        for finding in findings
    )

    assert all(
        finding.status == "unverified"
        for finding in findings
    )

    assert all(
        finding.evidence_reference
        for finding in findings
    )


def test_cron_parser_ignores_comments_and_invalid_lines(tmp_path):
    sample = tmp_path / "test_cron"

    sample.write_text(
        "# comment\n"
        "invalid\n"
        "*/5 * * * * /usr/bin/backup.sh\n"
    )

    events = parse_cron_file(str(sample))

    assert len(events) == 1


def test_cron_detection_detects_shell_script_in_tmp():
    event = NormalizedEvent(
        event_id="test-1",
        case_id="CASE-001",
        host_id="LINUX-001",
        platform="linux",
        severity="info",
        message="Cron job",
        event_type="cron_job",
        source="crontab",
        evidence_reference="crontab:line-1",
        metadata={
            "schedule": "@reboot",
            "user": "root",
            "command": "/bin/bash /dev/shm/startup.sh"
        }
    )

    findings = detect_suspicious_cron([event])

    assert len(findings) == 1
    assert findings[0].rule_id == "LINUX-CRON-001"
    assert findings[0].status == "unverified"
    assert findings[0].evidence_reference == "crontab:line-1"


def test_cron_detection_ignores_tmp_path_in_echo():
    event = NormalizedEvent(
        event_id="test-2",
        case_id="CASE-001",
        host_id="LINUX-001",
        platform="linux",
        severity="info",
        message="Cron job",
        event_type="cron_job",
        source="crontab",
        evidence_reference="crontab:line-2",
        metadata={
            "schedule": "* * * * *",
            "user": "root",
            "command": 'echo "/tmp/test"'
        }
    )

    findings = detect_suspicious_cron([event])

    assert len(findings) == 0


def test_cron_detection_ignores_empty_command():
    event = NormalizedEvent(
        event_id="test-3",
        case_id="CASE-001",
        host_id="LINUX-001",
        platform="linux",
        severity="info",
        message="Cron job",
        event_type="cron_job",
        source="crontab",
        evidence_reference="crontab:line-3",
        metadata={
            "schedule": "* * * * *",
            "user": "root",
            "command": ""
        }
    )

    findings = detect_suspicious_cron([event])

    assert len(findings) == 0
