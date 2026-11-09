#!/usr/bin/env python3
"""Linux Collector — read-only raw evidence collection for the DFIR pipeline.

Implements the team guide (Task 01 — Linux Collector):

    - Collect raw evidence from a Linux lab machine, safely and in an
      organized way. No analysis, no verdicts — the parser member and the
      detection rules consume this output later.
    - Sources (per the guide):
        * Authentication : /var/log/auth.log  or /var/log/secure
        * System logs    : /var/log/syslog    or /var/log/messages
        * Cron           : /etc/crontab, /etc/cron.d/, user crontabs
        * Systemd        : service names + state + unit file (metadata only)
        * SSH metadata   : sshd_config and authorized_keys (public keys only)
    - Read existing files only; a missing source is RECORDED, never fatal.
    - Every record carries: source path + line number; the collection adds
      host_id and a UTC timestamp.
    - Never modify the system: read-only file access, read-only systemctl
      queries, nothing is stopped, deleted, or edited.
    - NEVER collect private keys (id_rsa, id_ed25519, *.pem ...), passwords,
      or tokens. A final safety scan drops any record that contains a
      private-key marker before anything is written.
    - Output goes to a LOCAL folder (default: output/linux) which is
      gitignored — real logs must never be pushed to GitHub.

Usage:
    python3 collectors/linux/collector.py
    python3 collectors/linux/collector.py --output-dir output/linux \
        --host-id LINUX-LAB-01 --max-lines 500
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOL_NAME = "linux-collector"
TOOL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Source paths (per the team guide). The collector reads whichever exist.
# ---------------------------------------------------------------------------

AUTH_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]
SYSLOG_PATHS = ["/var/log/syslog", "/var/log/messages"]
CRON_FILES = ["/etc/crontab"]
CRON_DIRS = ["/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"]
SYSTEMD_DIRS = ["/etc/systemd/system", "/usr/lib/systemd/system"]
SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
AUTHORIZED_KEYS_DIRS = ["/root/.ssh", "/home/*/.ssh"]
AUTHORIZED_KEYS_NAME = "authorized_keys"

# Private-key protection: these file names are never read, and any record
# containing this marker is dropped by the final safety scan.
PRIVATE_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity"}
PRIVATE_KEY_MARKER = "PRIVATE KEY"


def _utc_now() -> str:
    """Current time as UTC ISO 8601 with the trailing Z the contract wants."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


# ---------------------------------------------------------------------------
# core reading helper
# ---------------------------------------------------------------------------

def read_lines_with_numbers(path: str | Path, max_lines: int = 500) -> list[dict]:
    """Read a text file and return records with line numbers.

    Each record: {"line_no": int, "source": str, "message": str}.
    Raises FileNotFoundError / PermissionError so the caller can record it —
    the collector never lets a bad source crash the whole run.
    """
    records: list[dict] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line_no, raw_line in enumerate(handle, start=1):
            if line_no > max_lines:
                break
            text = raw_line.rstrip("\r\n")
            if not text:
                continue
            records.append(
                {"line_no": line_no, "source": str(path), "message": text}
            )
    return records


def _safe_read(path: str | Path, max_lines: int) -> tuple[list[dict], str | None]:
    """read_lines_with_numbers but converts errors into a reason string."""
    try:
        return read_lines_with_numbers(path, max_lines), None
    except FileNotFoundError:
        return [], "file not found"
    except PermissionError:
        return [], "permission denied (need root or file owner)"
    except OSError as exc:
        return [], f"read error: {exc}"


def _redact_private_keys(records: list[dict]) -> tuple[list[dict], int]:
    """Drop any record containing a private-key marker. Returns (clean, n)."""
    clean: list[dict] = []
    redacted = 0
    for record in records:
        if PRIVATE_KEY_MARKER in record.get("message", ""):
            redacted += 1
            continue
        clean.append(record)
    return clean, redacted


def _make_source_result(
    name: str,
    collection_type: str,
    host_id: str,
    collected_at: str,
    records: list[dict],
    sources: list[str],
    status: str,
    reason: str | None = None,
    method: str | None = None,
    redacted: int = 0,
) -> dict:
    result: dict[str, Any] = {
        "source_name": name,
        "collection_type": collection_type,
        "host_id": host_id,
        "collected_at": collected_at,
        "status": status,
        "sources": sources,
        "record_count": len(records),
        "records": records,
    }
    if sources:
        result["source"] = sources[0]
    if reason:
        result["reason"] = reason
    if method:
        result["method"] = method
    if redacted:
        result["redacted"] = redacted
    return result


# ---------------------------------------------------------------------------
# per-source collectors (each returns one source result dict)
# ---------------------------------------------------------------------------

def collect_auth_log(host_id: str, collected_at: str,
                     max_lines: int, paths: list[str] | None = None) -> dict:
    """Authentication log: first existing of /var/log/auth.log, /var/log/secure."""
    paths = paths if paths is not None else AUTH_LOG_PATHS
    for path in paths:
        if os.path.exists(path):
            records, error = _safe_read(path, max_lines)
            if error:
                return _make_source_result(
                    "auth_log", "linux_auth_log", host_id, collected_at,
                    [], [path], "error", reason=error)
            records, redacted = _redact_private_keys(records)
            status = "collected" if records else "empty"
            return _make_source_result(
                "auth_log", "linux_auth_log", host_id, collected_at,
                records, [path], status,
                reason=None if records else "file exists but no records read",
                redacted=redacted)
    return _make_source_result(
        "auth_log", "linux_auth_log", host_id, collected_at,
        [], [], "missing", reason=f"none of {paths} exist on this host")


def collect_syslog(host_id: str, collected_at: str,
                   max_lines: int, paths: list[str] | None = None) -> dict:
    """System log: first existing of /var/log/syslog, /var/log/messages."""
    paths = paths if paths is not None else SYSLOG_PATHS
    for path in paths:
        if os.path.exists(path):
            records, error = _safe_read(path, max_lines)
            if error:
                return _make_source_result(
                    "syslog", "linux_syslog", host_id, collected_at,
                    [], [path], "error", reason=error)
            records, redacted = _redact_private_keys(records)
            status = "collected" if records else "empty"
            return _make_source_result(
                "syslog", "linux_syslog", host_id, collected_at,
                records, [path], status,
                reason=None if records else "file exists but no records read",
                redacted=redacted)
    return _make_source_result(
        "syslog", "linux_syslog", host_id, collected_at,
        [], [], "missing", reason=f"none of {paths} exist on this host")


def _cron_file_paths(directories: list[str] | None = None) -> list[str]:
    """Expand /etc/crontab + /etc/cron.d/* + user crontabs (existing only)."""
    directories = directories if directories is not None else CRON_DIRS
    paths = [p for p in CRON_FILES if os.path.exists(p)]
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        for entry in sorted(os.listdir(directory)):
            full = os.path.join(directory, entry)
            if os.path.isfile(full) and not os.path.islink(full):
                paths.append(full)
    return paths


def collect_cron(host_id: str, collected_at: str, max_lines: int,
                 paths: list[str] | None = None) -> dict:
    """Cron files: /etc/crontab + /etc/cron.d/* + user crontabs (if permitted)."""
    paths = paths if paths is not None else _cron_file_paths()
    if not paths:
        return _make_source_result(
            "cron", "linux_cron", host_id, collected_at, [], [],
            "missing", reason="no cron files found or readable")
    records: list[dict] = []
    errors: list[str] = []
    for path in paths:
        file_records, error = _safe_read(path, max_lines)
        records.extend(file_records)
        if error:
            errors.append(f"{path}: {error}")
    records, redacted = _redact_private_keys(records)
    status = "collected" if records else "empty"
    reason = "; ".join(errors) if errors else None
    return _make_source_result(
        "cron", "linux_cron", host_id, collected_at,
        records, paths, status, reason=reason, redacted=redacted)


def _systemd_via_file_scan(directories: list[str], max_lines: int) -> list[dict]:
    """Fallback: read .service unit files (name + Description only)."""
    records: list[dict] = []
    seen: set[str] = set()
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        for full in sorted(glob.glob(os.path.join(directory, "*.service"))):
            name = os.path.basename(full)
            if name in seen:
                continue
            seen.add(name)
            description = ""
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        text = line.strip()
                        if text.startswith("Description="):
                            description = text.split("=", 1)[1]
                            break
            except OSError:
                description = "(unreadable)"
            if len(records) >= max_lines:
                break
            records.append({
                "line_no": 1,
                "source": full,
                "message": f"{name}: {description or '(no description)'}",
            })
    return records


def collect_systemd(host_id: str, collected_at: str, max_lines: int,
                    directories: list[str] | None = None) -> dict:
    """Systemd metadata: service names + state. Read-only queries only."""
    directories = directories if directories is not None else SYSTEMD_DIRS
    method = "systemctl"
    records: list[dict] = []
    try:
        output = subprocess.run(
            ["systemctl", "list-unit-files", "--type=service",
             "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        if output.returncode == 0 and output.stdout.strip():
            for index, line in enumerate(output.stdout.splitlines(), start=1):
                if index > max_lines:
                    break
                text = line.strip()
                if text:
                    records.append({
                        "line_no": index,
                        "source": "systemctl list-unit-files",
                        "message": text,
                    })
    except (OSError, subprocess.SubprocessError):
        records = []

    if not records:
        method = "file-scan"
        records = _systemd_via_file_scan(directories, max_lines)

    records, redacted = _redact_private_keys(records)
    if not records:
        return _make_source_result(
            "systemd_services", "linux_systemd_services", host_id,
            collected_at, [], [], "missing",
            reason="systemctl unavailable and no .service files found",
            method=method)
    return _make_source_result(
        "systemd_services", "linux_systemd_services", host_id, collected_at,
        records, [records[0]["source"]], "collected", method=method,
        redacted=redacted)


def _authorized_keys_paths() -> list[str]:
    """Existing authorized_keys files under /root and /home/* (public keys)."""
    paths: list[str] = []
    patterns = AUTHORIZED_KEYS_DIRS
    for pattern in patterns:
        for ssh_dir in sorted(glob.glob(pattern)):
            candidate = os.path.join(ssh_dir, AUTHORIZED_KEYS_NAME)
            if os.path.isfile(candidate):
                paths.append(candidate)
    return paths


def collect_ssh_metadata(host_id: str, collected_at: str, max_lines: int,
                         include: bool = True) -> dict:
    """SSH metadata: sshd_config + authorized_keys (public keys only).

    Private keys (id_rsa, id_ed25519, ...) are NEVER read — they are not in
    the source list, and the safety scan drops private-key content anyway.
    """
    if not include:
        return _make_source_result(
            "ssh_metadata", "linux_ssh_metadata", host_id, collected_at,
            [], [], "skipped", reason="disabled with --no-ssh-metadata")
    paths = [p for p in [SSHD_CONFIG_PATH] if os.path.exists(p)]
    paths.extend(_authorized_keys_paths())
    if not paths:
        return _make_source_result(
            "ssh_metadata", "linux_ssh_metadata", host_id, collected_at,
            [], [], "missing",
            reason="no sshd_config or authorized_keys found")
    records: list[dict] = []
    errors: list[str] = []
    for path in paths:
        file_records, error = _safe_read(path, max_lines)
        records.extend(file_records)
        if error:
            errors.append(f"{path}: {error}")
    records, redacted = _redact_private_keys(records)
    status = "collected" if records else "empty"
    return _make_source_result(
        "ssh_metadata", "linux_ssh_metadata", host_id, collected_at,
        records, paths, status,
        reason="; ".join(errors) if errors else None, redacted=redacted)


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def run_collection(output_dir: str | Path, host_id: str | None = None,
                   max_lines: int = 500, include_ssh: bool = True,
                   auth_paths: list[str] | None = None,
                   syslog_paths: list[str] | None = None,
                   cron_paths: list[str] | None = None,
                   systemd_dirs: list[str] | None = None,
                   ) -> dict:
    """Run all collectors and write raw JSON files + collection_summary.json.

    The *_paths / *_dirs overrides exist for tests and lab runs on custom
    fixtures; production runs use the default system paths.

    Returns the summary dict. Output folder is created if needed; real logs
    stay LOCAL (output/ is gitignored — never push them to GitHub).
    """
    host_id = host_id or socket.gethostname() or "LINUX-UNKNOWN"
    collected_at = _utc_now()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    results = [
        collect_auth_log(host_id, collected_at, max_lines, paths=auth_paths),
        collect_syslog(host_id, collected_at, max_lines, paths=syslog_paths),
        collect_cron(host_id, collected_at, max_lines, paths=cron_paths),
        collect_systemd(host_id, collected_at, max_lines,
                        directories=systemd_dirs),
        collect_ssh_metadata(host_id, collected_at, max_lines,
                             include=include_ssh),
    ]

    summary: dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "host_id": host_id,
        "collected_at": collected_at,
        "max_lines": max_lines,
        "sources": {},
        "totals": {"records": 0, "redacted": 0},
    }

    file_stems = {
        "auth_log": "auth_log",
        "syslog": "syslog",
        "cron": "cron",
        "systemd_services": "systemd_services",
        "ssh_metadata": "ssh_metadata",
    }
    for result in results:
        name = result["source_name"]
        records = result.get("records", [])
        summary["sources"][name] = {
            "status": result["status"],
            "collection_type": result["collection_type"],
            "record_count": len(records),
            "sources": result["sources"],
        }
        if result.get("reason"):
            summary["sources"][name]["reason"] = result["reason"]
        if result.get("method"):
            summary["sources"][name]["method"] = result["method"]
        summary["totals"]["records"] += len(records)
        summary["totals"]["redacted"] += result.get("redacted", 0)

        out_file = output_path / f"{file_stems[name]}.json"
        with out_file.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)

    with (output_path / "collection_summary.json").open(
        "w", encoding="utf-8"
    ) as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Linux Collector — read-only raw evidence collection "
                    "(DFIR pipeline, Task 01).")
    parser.add_argument("--output-dir", default="output/linux",
                        help="local output folder (default: output/linux) "
                             "— gitignored, never pushed to GitHub")
    parser.add_argument("--host-id", default=None,
                        help="host identifier (default: this machine's "
                             "hostname)")
    parser.add_argument("--max-lines", type=int, default=500,
                        help="max lines read per source (default: 500)")
    parser.add_argument("--no-ssh-metadata", action="store_true",
                        help="skip the SSH metadata source")
    args = parser.parse_args(argv)

    summary = run_collection(
        args.output_dir, host_id=args.host_id,
        max_lines=args.max_lines, include_ssh=not args.no_ssh_metadata,
    )

    print(f"[linux-collector] host        : {summary['host_id']}")
    print(f"[linux-collector] time (UTC)  : {summary['collected_at']}")
    print(f"[linux-collector] output dir  : {args.output_dir}")
    print(f"[linux-collector] total records: {summary['totals']['records']}"
          f" (redacted: {summary['totals']['redacted']})")
    for name, info in summary["sources"].items():
        line = f"  {name:<18} {info['status']:<10} {info['record_count']:>5} records"
        if info.get("reason"):
            line += f"  ({info['reason']})"
        print(line)
    print("[linux-collector] NOTE: raw logs stay local (gitignored). "
          "Only sanitized samples go to GitHub.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
