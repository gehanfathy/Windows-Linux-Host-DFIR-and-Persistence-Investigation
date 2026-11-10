from core.normalized_event import NormalizedEvent
from parsers.linux.ssh_parser import parse_authorized_keys


def test_ssh_parser():
    events = parse_authorized_keys("samples/linux/authorized_keys")

    assert len(events) == 2

    for event in events:
        assert isinstance(event, NormalizedEvent)
        assert event.platform == "linux"
        assert event.event_type == "ssh_authorized_key"
        assert event.evidence_reference

    assert events[0].metadata["key_type"] == "ssh-ed25519"
    assert events[0].metadata["comment"] == "user1@example"
    assert events[0].evidence_reference == "authorized_keys:line-1"


def test_ssh_parser_extracts_key_ids():
    events = parse_authorized_keys("samples/linux/authorized_keys")

    for event in events:
        assert event.metadata.get("key_id")
        assert event.metadata["key_type"]
        assert event.metadata.get("line_number")
