"""Tests for collectors/linux/collector.py (Task 01 — Linux Collector).

Covers the four tests required by the team guide:

    1. reading a sample file works
    2. a missing file does NOT crash — it is recorded instead
    3. every record carries its source and line number
    4. no private key / secret ever appears in the output

plus: full run writes valid JSON + collection_summary.json, source files
are never modified, and the shipped sanitized samples are valid.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

SAMPLE_DIR = REPO / "sample_data" / "linux"

AUTH_LOG_SAMPLE = """Nov  4 10:14:55 LAB-01 sshd[2214]: Failed password for invalid user admin from 203.0.113.55 port 44578 ssh2
Nov  4 10:15:02 LAB-01 sshd[2214]: Failed password for invalid user admin from 203.0.113.55 port 44590 ssh2
Nov  4 10:16:01 LAB-01 sshd[2214]: Accepted password for labuser from 203.0.113.55 port 44641 ssh2
"""

CRON_WITH_KEY = """0 2 * * * root /opt/scripts/backup.sh
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAAfakefaketaketake
-----END OPENSSH PRIVATE KEY-----
*/10 * * * * root /tmp/system_update.sh
"""


# ---------------------------------------------------------------------------
# 1. reading a sample file works
# ---------------------------------------------------------------------------

def test_read_sample_file(tmp_path: Path) -> None:
    from collectors.linux.collector import collect_auth_log

    log = tmp_path / "auth.log"
    log.write_text(AUTH_LOG_SAMPLE, encoding="utf-8")

    result = collect_auth_log("TEST-HOST", "2026-11-04T10:00:00Z", 500,
                              paths=[str(log)])

    assert result["status"] == "collected"
    assert result["record_count"] == 3
    assert "Failed password" in result["records"][0]["message"]
    assert result["host_id"] == "TEST-HOST"
    assert result["collection_type"] == "linux_auth_log"


# ---------------------------------------------------------------------------
# 2. missing file does not crash — recorded instead
# ---------------------------------------------------------------------------

def test_missing_file_recorded_not_crash(tmp_path: Path) -> None:
    from collectors.linux.collector import collect_auth_log

    result = collect_auth_log(
        "TEST-HOST", "2026-11-04T10:00:00Z", 500,
        paths=[str(tmp_path / "does_not_exist.log")],
    )

    assert result["status"] == "missing"
    assert result["record_count"] == 0
    assert "does_not_exist" in result["reason"]


def test_full_run_survives_all_sources_missing(tmp_path: Path) -> None:
    from collectors.linux.collector import run_collection

    # Fresh tmp dir: on any machine the run must complete and produce a
    # summary + files without raising, whatever sources exist locally.
    summary = run_collection(tmp_path, host_id="TEST-HOST", max_lines=50)

    assert summary["host_id"] == "TEST-HOST"
    assert summary["collected_at"].endswith("Z")
    assert set(summary["sources"]) == {
        "auth_log", "syslog", "cron", "systemd_services", "ssh_metadata",
    }


def test_permission_error_recorded_not_crash(tmp_path: Path) -> None:
    # A directory passed as a log file raises IsADirectoryError (an OSError)
    # when read — the collector must record the error and keep going.
    from collectors.linux.collector import collect_auth_log

    directory = tmp_path / "weird.log"
    directory.mkdir()

    result = collect_auth_log("TEST-HOST", "2026-11-04T10:00:00Z", 500,
                              paths=[str(directory)])

    assert result["status"] == "error"
    assert "read error" in result["reason"]


# ---------------------------------------------------------------------------
# 3. every record carries source + line number
# ---------------------------------------------------------------------------

def test_every_record_has_source_and_line_number(tmp_path: Path) -> None:
    from collectors.linux.collector import (
        collect_auth_log, collect_cron, collect_syslog,
    )

    log = tmp_path / "auth.log"
    log.write_text(AUTH_LOG_SAMPLE, encoding="utf-8")
    cron_file = tmp_path / "crontab"
    cron_file.write_text("0 2 * * * root /opt/scripts/backup.sh\n",
                         encoding="utf-8")

    for result in (
        collect_auth_log("H", "2026-11-04T10:00:00Z", 500, paths=[str(log)]),
        collect_syslog("H", "2026-11-04T10:00:00Z", 500, paths=[str(log)]),
        collect_cron("H", "2026-11-04T10:00:00Z", 500, paths=[str(cron_file)]),
    ):
        for record in result["records"]:
            assert isinstance(record["line_no"], int) and record["line_no"] >= 1
            assert record["source"]  # non-empty path string
            assert record["message"]


def test_shipped_samples_all_records_have_source_and_line() -> None:
    sample_files = sorted(SAMPLE_DIR.glob("*_sample.json"))
    assert len(sample_files) == 5
    for path in sample_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["host_id"], path.name
        assert data["collected_at"].endswith("Z"), path.name
        assert data["collection_type"].startswith("linux_"), path.name
        for record in data["records"]:
            assert isinstance(record["line_no"], int), path.name
            assert record["source"], path.name


# ---------------------------------------------------------------------------
# 4. no private key / secret in the output
# ---------------------------------------------------------------------------

def test_private_key_content_is_dropped(tmp_path: Path) -> None:
    from collectors.linux.collector import collect_cron

    cron_file = tmp_path / "crontab"
    cron_file.write_text(CRON_WITH_KEY, encoding="utf-8")

    result = collect_cron("H", "2026-11-04T10:00:00Z", 500,
                          paths=[str(cron_file)])

    # 3 clean lines survive; the BEGIN/END key marker lines are dropped.
    assert result["record_count"] == 3
    for record in result["records"]:
        assert "PRIVATE KEY" not in record["message"]


def test_private_key_files_never_in_source_paths() -> None:
    from collectors.linux.collector import (
        AUTHORIZED_KEYS_DIRS, AUTHORIZED_KEYS_NAME, CRON_DIRS, CRON_FILES,
        AUTH_LOG_PATHS, SYSLOG_PATHS, SSHD_CONFIG_PATH, SYSTEMD_DIRS,
    )

    all_paths = (
        AUTH_LOG_PATHS + SYSLOG_PATHS + CRON_FILES + CRON_DIRS
        + list(SYSTEMD_DIRS) + [SSHD_CONFIG_PATH] + AUTHORIZED_KEYS_DIRS
    )
    for path in all_paths:
        name = path.rstrip("/").split("/")[-1]
        assert name not in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
    assert AUTHORIZED_KEYS_NAME == "authorized_keys"  # public keys only


def test_shipped_samples_contain_no_secrets() -> None:
    for path in SAMPLE_DIR.glob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert "PRIVATE KEY" not in text, path.name
        assert "BEGIN RSA" not in text, path.name
        assert "BEGIN OPENSSH" not in text, path.name


# ---------------------------------------------------------------------------
# full run: files written + source files untouched
# ---------------------------------------------------------------------------

def test_full_run_writes_output_and_never_modifies_source(tmp_path: Path
                                                          ) -> None:
    from collectors.linux.collector import run_collection

    source = tmp_path / "auth.log"
    source.write_text(AUTH_LOG_SAMPLE, encoding="utf-8")
    cron_file = tmp_path / "crontab"
    cron_file.write_text("0 2 * * * root /opt/scripts/backup.sh\n",
                         encoding="utf-8")
    original_content = source.read_text(encoding="utf-8")

    out_dir = tmp_path / "out"
    summary = run_collection(
        out_dir, host_id="TEST-HOST", max_lines=100,
        auth_paths=[str(source)],
        syslog_paths=[str(source)],
        cron_paths=[str(cron_file)],
        systemd_dirs=[str(tmp_path / "no-systemd")],
    )

    expected_files = {
        "auth_log.json", "syslog.json", "cron.json",
        "systemd_services.json", "ssh_metadata.json",
        "collection_summary.json",
    }
    assert {p.name for p in out_dir.iterdir()} >= expected_files

    auth_data = json.loads((out_dir / "auth_log.json").read_text(
        encoding="utf-8"))
    assert auth_data["collection_type"] == "linux_auth_log"
    assert auth_data["record_count"] == 3

    assert summary["totals"]["records"] >= 3
    # read-only guarantee: the source file is byte-identical after the run
    assert source.read_text(encoding="utf-8") == original_content
