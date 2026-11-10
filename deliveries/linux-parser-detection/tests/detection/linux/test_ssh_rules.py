import pytest

from parsers.linux.ssh_parser import parse_authorized_keys
from detection.linux.ssh_rules import detect_unexpected_authorized_keys


def test_detects_unexpected_authorized_key(tmp_path):
    keys_file = tmp_path / "authorized_keys"

    keys_file.write_text(
        "ssh-ed25519 AAAATESTKEYDATA user1@example\n"
        "ssh-rsa AAAAOTHERKEYDATA user2@example\n",
        encoding="utf-8"
    )

    events = parse_authorized_keys(str(keys_file))

    expected_key_ids = {events[0].metadata["key_id"]}

    findings = detect_unexpected_authorized_keys(
        events,
        expected_key_ids
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "LINUX-SSH-001"
    assert finding.status == "unverified"
    assert finding.severity == "medium"
    assert finding.metadata["comment"] == "user2@example"
    assert finding.evidence_reference == "authorized_keys:line-2"


def test_ignores_keys_in_expected_baseline(tmp_path):
    keys_file = tmp_path / "authorized_keys"

    keys_file.write_text(
        "ssh-ed25519 AAAATESTKEYDATA user1@example\n",
        encoding="utf-8"
    )

    events = parse_authorized_keys(str(keys_file))
    expected_key_ids = {events[0].metadata["key_id"]}

    findings = detect_unexpected_authorized_keys(
        events,
        expected_key_ids
    )

    assert findings == []


def test_requires_expected_baseline(tmp_path):
    keys_file = tmp_path / "authorized_keys"

    keys_file.write_text(
        "ssh-ed25519 AAAATESTKEYDATA user1@example\n",
        encoding="utf-8"
    )

    events = parse_authorized_keys(str(keys_file))

    with pytest.raises(ValueError):
        detect_unexpected_authorized_keys(events, None)


def test_finding_does_not_expose_public_key_data(tmp_path):
    keys_file = tmp_path / "authorized_keys"

    public_key = "AAAATESTKEYDATA"

    keys_file.write_text(
        f"ssh-ed25519 {public_key} user1@example\n",
        encoding="utf-8"
    )

    events = parse_authorized_keys(str(keys_file))
    findings = detect_unexpected_authorized_keys(events, set())

    assert len(findings) == 1
    assert public_key not in findings[0].message
    assert public_key not in findings[0].evidence_reference
    assert public_key not in str(findings[0].metadata)
