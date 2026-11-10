
from parsers.linux.systemd_parser import parse_systemd_services


def test_systemd_parser_reads_all_services():
    events = parse_systemd_services(
        "samples/linux/systemd_services.txt"
    )

    assert len(events) == 3

    names = [event.metadata["service_name"] for event in events]

    assert "cron.service" in names
    assert "accounts-daemon.service" in names
    assert "apparmor.service" in names


def test_systemd_parser_extracts_service_details():
    events = parse_systemd_services(
        "samples/linux/systemd_services.txt"
    )

    cron = next(
        event for event in events
        if event.metadata["service_name"] == "cron.service"
    )

    assert cron.event_type == "systemd_service"
    assert cron.metadata["status"] == "active/running"
    assert cron.metadata["active_state"] == "active"
    assert cron.metadata["sub_state"] == "running"
    assert cron.metadata["load_state"] == "loaded"
    assert cron.metadata["unit_path"] == (
        "/usr/lib/systemd/system/cron.service"
    )
    assert cron.evidence_reference is not None


def test_systemd_parser_handles_missing_fragment_path(tmp_path):
    sample = tmp_path / "systemd.txt"

    sample.write_text(
        "Id=test.service\n"
        "ActiveState=inactive\n"
        "SubState=dead\n",
        encoding="utf-8"
    )

    events = parse_systemd_services(str(sample))

    assert len(events) == 1
    assert events[0].metadata["unit_path"] is None
    assert events[0].metadata["status"] == "inactive/dead"


def test_systemd_parser_ignores_block_without_service_id(tmp_path):
    sample = tmp_path / "systemd.txt"

    sample.write_text(
        "ActiveState=active\n"
        "SubState=running\n",
        encoding="utf-8"
    )

    events = parse_systemd_services(str(sample))

    assert events == []
