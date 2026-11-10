
from core.normalized_event import NormalizedEvent
from detection.linux.login_rules import detect_repeated_failed_logins


def create_event(event_id, event_type, ip, timestamp, line):
    return NormalizedEvent(
        event_id=event_id,
        case_id="CASE-001",
        host_id="LINUX-001",
        platform="linux",
        severity="medium",
        message="Test login event",
        event_type=event_type,
        timestamp=timestamp,
        source="auth.log",
        evidence_reference=f"auth.log:line-{line}",
        metadata={"source_ip": ip}
    )


def test_detects_repeated_failed_logins():
    events = [
        create_event(
            f"event-{i}",
            "failed_login",
            "192.168.1.20",
            f"2026-11-04T10:1{i}:00Z",
            i
        )
        for i in range(5)
    ]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "LINUX-AUTH-001"
    assert finding.status == "unverified"
    assert finding.severity == "medium"
    assert finding.metadata["source_ip"] == "192.168.1.20"
    assert finding.metadata["failed_attempts"] == 5
    assert "auth.log:line-0" in finding.evidence_reference


def test_ignores_different_source_ips():
    events = [
        create_event(
            f"event-{i}",
            "failed_login",
            f"192.168.1.{i}",
            f"2026-11-04T10:1{i}:00Z",
            i
        )
        for i in range(5)
    ]

    findings = detect_repeated_failed_logins(events)

    assert findings == []


def test_ignores_attempts_outside_time_window():
    events = [
        create_event(
            f"event-{i}",
            "failed_login",
            "192.168.1.20",
            f"2026-11-04T10:{i * 2:02d}:00Z",
            i
        )
        for i in range(5)
    ]

    findings = detect_repeated_failed_logins(events)

    assert findings == []


def test_ignores_successful_logins():
    events = [
        create_event(
            f"event-{i}",
            "successful_login",
            "192.168.1.20",
            f"2026-11-04T10:1{i}:00Z",
            i
        )
        for i in range(5)
    ]

    findings = detect_repeated_failed_logins(events)

    assert findings == []
