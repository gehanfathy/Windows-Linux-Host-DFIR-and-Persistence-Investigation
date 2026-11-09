"""End-to-end Linux chain: sample_data/linux -> parser -> detection rules
-> output files, mirroring the Windows integration test (team guide 04)."""

import json
from pathlib import Path

from parsers.linux.parser import parse_directory
from detection.linux import rules

RE = Path(__file__).resolve().parents[2]


def test_linux_end_to_end_pipeline(tmp_path):
    events, warnings = parse_directory(
        RE / "sample_data" / "linux", case_id="case-000002")

    assert len(events) == 30
    assert len(warnings) == 1  # cron header comment
    assert all(e["platform"] == "linux" for e in events)

    findings, iocs = rules.run_detection(events, case_id="case-000002")
    assert len(findings) == 5
    assert len(iocs) == 5
    assert all(f["case_id"] == "case-000002" for f in findings)
    assert all(f["status"] == "unverified" for f in findings)

    # Persist pipeline output the way run_linux_demo.py does.
    events_path = tmp_path / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    (tmp_path / "findings.json").write_text(
        json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")
    (tmp_path / "iocs.json").write_text(
        json.dumps(iocs, ensure_ascii=False, indent=2), encoding="utf-8")

    # Reload from disk and verify round-trip integrity.
    reloaded = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(reloaded) == 30
    assert reloaded[0]["event_id"] == "evt-lin-000001"
    assert reloaded[-1]["event_id"] == "evt-lin-000030"

    reloaded_findings = json.loads(
        (tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert len(reloaded_findings) == 5
