from detection.linux.login_rules import detect_repeated_failed_logins
from core.normalized_event import NormalizedEvent
from parsers.linux.auth_parser import parse_auth_log


def test_auth_parser_returns_normalized_events():
    events = parse_auth_log("samples/linux/auth.log")

    assert len(events) == 4

    for event in events:
        assert isinstance(event, NormalizedEvent)


def test_brute_force_detection():
    events = parse_auth_log("samples/linux/auth_bruteforce.log")

    findings = detect_repeated_failed_logins(
        events,
        threshold=3,
        year=2026
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "LINUX-AUTH-001"
    assert findings[0].status == "unverified"
    assert findings[0].metadata["failed_attempts"] == 3
    assert findings[0].severity == "medium"
    assert len(findings[0].evidence_reference.split(", ")) == 3


def test_brute_force_ignores_attempts_outside_window():
    events = parse_auth_log("samples/linux/auth_outside_window.log")

    findings = detect_repeated_failed_logins(
        events,
        threshold=3,
        year=2026
    )

    assert len(findings) == 0


def test_auth_parser_detects_event_types():
    events = parse_auth_log("samples/linux/auth.log")

    assert [e.event_type for e in events] == [
        "failed_login",
        "successful_login",
        "invalid_user",
        "sudo_activity",
    ]


def test_auth_parser_extracts_login_details():
    events = parse_auth_log("samples/linux/auth.log")

    failed = events[0]
    assert failed.metadata["username"] == "admin"
    assert failed.metadata["source_ip"] == "192.168.1.20"
    assert failed.metadata["source_port"] == 22
    assert failed.metadata["process"] == "sshd"
    assert failed.timestamp == "Nov  4 10:15:00"
    assert failed.evidence_reference == "auth.log:line-1"

    success = events[1]
    assert success.metadata["username"] == "ahmed"
    assert success.metadata["source_ip"] == "192.168.1.30"


def test_auth_parser_extracts_sudo_details():
    events = parse_auth_log("samples/linux/auth.log")

    sudo = events[3]
    assert sudo.metadata["username"] == "ahmed"
    assert sudo.metadata["command"] == "/usr/bin/id"


def test_auth_parser_handles_sudo_without_pid_and_ignores_pam_noise(tmp_path):
    sample = tmp_path / "auth.log"
    sample.write_text(
        "Nov  4 10:19:00 server sudo: ahmed : TTY=pts/0 ; PWD=/home/ahmed ; "
        "USER=root ; COMMAND=/usr/bin/apt update\n"
        "Nov  4 10:19:05 server sudo: pam_unix(sudo:session): "
        "session opened for user root(uid=0) by ahmed(uid=1000)\n",
        encoding="utf-8"
    )

    events = parse_auth_log(str(sample))

    assert len(events) == 1
    assert events[0].metadata["command"] == "/usr/bin/apt update"


def test_auth_parser_ignores_garbage_lines_without_crashing(tmp_path):
    sample = tmp_path / "auth.log"
    sample.write_text(
        "this line is garbage and must be skipped\n"
        "\n"
        "Nov  4 10:15:00 server sshd[1]: Failed password for admin "
        "from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8"
    )

    events = parse_auth_log(str(sample))

    assert len(events) == 1
