"""Integration review tests for the teammate delivery preserved in
`deliveries/linux-parser-detection/` (Linux parser & detection module).

Two goals:

1. Smoke-check that the delivered parsers and detection rules still run
   inside this repository (they are loaded by file path so the teammate's
   `parsers.linux` / `detection.linux` import namespaces never collide with
   the canonical ones).
2. Pin the documented schema-compatibility gaps from
   `deliveries/linux-parser-detection/DELIVERY-NOTE.md`, so any change on
   either side is caught during the integration phase.
"""

import importlib.util
import sys
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.models.schemas import NormalizedEvent


REPO_ROOT = Path(__file__).resolve().parents[2]

DELIVERY_ROOT = REPO_ROOT / "deliveries" / "linux-parser-detection"

requires_delivery = pytest.mark.skipif(
    not DELIVERY_ROOT.exists(),
    reason="teammate delivery folder is not present",
)


@pytest.fixture()
def teammate():
    """Load the delivery's parser/rule modules by file path."""
    sys.path.insert(0, str(DELIVERY_ROOT))

    try:
        def load(relative_path: str, module_name: str):
            spec = importlib.util.spec_from_file_location(
                module_name, DELIVERY_ROOT / relative_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

        return SimpleNamespace(
            auth_parser=load("parsers/linux/auth_parser.py", "teammate_auth_parser"),
            cron_parser=load("parsers/linux/cron_parser.py", "teammate_cron_parser"),
            login_rules=load("detection/linux/login_rules.py", "teammate_login_rules"),
        )
    finally:
        sys.path.remove(str(DELIVERY_ROOT))


# ---------------------------------------------------------------------------
# 1. smoke checks — the delivery still runs inside this repository
# ---------------------------------------------------------------------------

@requires_delivery
def test_delivery_files_present():
    for relative in [
        "README.md",
        "DELIVERY-NOTE.md",
        "core/normalized_event.py",
        "core/normalized_finding.py",
        "parsers/linux/auth_parser.py",
        "detection/linux/login_rules.py",
        "samples/linux/auth_bruteforce.log",
    ]:
        assert (DELIVERY_ROOT / relative).exists(), f"missing: {relative}"


@requires_delivery
def test_teammate_auth_parser_produces_linux_events(teammate):
    events = teammate.auth_parser.parse_auth_log(
        str(DELIVERY_ROOT / "samples/linux/auth_bruteforce.log")
    )

    assert len(events) == 3

    for event in events:
        assert event.platform == "linux"
        assert event.event_type == "failed_login"
        assert event.evidence_reference.startswith("auth.log:line-")
        assert event.metadata["source_ip"]


@requires_delivery
def test_teammate_bruteforce_rule_produces_finding(teammate):
    events = teammate.auth_parser.parse_auth_log(
        str(DELIVERY_ROOT / "samples/linux/auth_bruteforce.log")
    )

    findings = teammate.login_rules.detect_repeated_failed_logins(
        events, threshold=3, year=2026
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "LINUX-AUTH-001"
    assert findings[0].status == "unverified"
    assert findings[0].severity == "medium"
    assert findings[0].metadata["failed_attempts"] == 3


@requires_delivery
def test_teammate_cron_parser_smoke(teammate):
    events = teammate.cron_parser.parse_cron_file(
        str(DELIVERY_ROOT / "samples/linux/crontab")
    )

    assert len(events) == 4


# ---------------------------------------------------------------------------
# 2. pinned schema-compatibility gaps (see DELIVERY-NOTE.md)
# ---------------------------------------------------------------------------

@requires_delivery
def test_gap_timestamp_is_syslog_string_not_iso(teammate):
    """Canonical NormalizedEvent requires an ISO datetime; the delivery
    keeps the raw syslog timestamp, so validation must fail."""
    events = teammate.auth_parser.parse_auth_log(
        str(DELIVERY_ROOT / "samples/linux/auth.log")
    )

    raw = asdict(events[0])

    with pytest.raises(Exception) as error:
        NormalizedEvent(**raw)

    assert "timestamp" in str(error.value)


@requires_delivery
def test_gap_sudo_severity_info_is_not_canonical(teammate):
    """Even with a valid ISO timestamp, the delivery's 'info' severity
    (sudo events) is outside the canonical low/medium/high/critical set."""
    events = teammate.auth_parser.parse_auth_log(
        str(DELIVERY_ROOT / "samples/linux/auth.log")
    )

    sudo_event = next(e for e in events if e.event_type == "sudo_activity")
    raw = asdict(sudo_event)
    raw["timestamp"] = "2026-11-04T10:19:00+00:00"

    with pytest.raises(Exception) as error:
        NormalizedEvent(**raw)

    assert "severity" in str(error.value)


@requires_delivery
def test_gap_finding_missing_canonical_fields(teammate):
    """The delivery's finding model has no case_id / host_id / platform,
    which the canonical NormalizedFinding requires."""
    events = teammate.auth_parser.parse_auth_log(
        str(DELIVERY_ROOT / "samples/linux/auth_bruteforce.log")
    )

    findings = teammate.login_rules.detect_repeated_failed_logins(
        events, threshold=3, year=2026
    )

    raw = asdict(findings[0])

    for missing_field in ["case_id", "host_id", "platform"]:
        assert missing_field not in raw
