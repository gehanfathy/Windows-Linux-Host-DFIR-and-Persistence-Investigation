"""
Linux Parser — raw collected evidence -> NormalizedEvent (DFIR Data Contract).

Input files (produced by collectors/linux/collector.py, or provided as
sanitized samples under sample_data/linux/). Each file is a JSON object
written by the collector:

    auth_log.json           (collection_type: linux_auth_log)
    syslog.json             (collection_type: linux_syslog)
    cron.json               (collection_type: linux_cron)
    systemd_services.json   (collection_type: linux_systemd_services)
    ssh_metadata.json       (collection_type: linux_ssh_metadata)

Every collector file carries a "records" list; each record is
{"line_no": int, "source": "<path>", "message": "<raw log line>"}.

Output: a JSONL file where every line is a validated NormalizedEvent dict
matching docs/DATA_CONTRACT.md (platform = "linux").

Design rules (per the team guides):
    - Unparsable or incomplete records are logged and skipped, never crash.
    - Missing fields are never invented.
    - Timestamps: auth/syslog lines start with a syslog date ("Nov  4
      10:14:55") that has no year and no timezone. The parser takes the
      year from the file's "collected_at" and interprets the time as UTC.
      Snapshot sources (cron, systemd, sshd_config, authorized_keys) use
      the file's "collected_at" as the event time. Both cases always end
      as UTC ISO 8601 ("...Z").
    - Every event carries an evidence_reference back to the raw evidence
      (e.g. "/var/log/auth.log:line-4").

Usage:
    python parsers/linux/parser.py --input sample_data/linux \
        --out output/linux/events.jsonl --case-id case-000001
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from app.models.schemas import NormalizedEvent  # type: ignore

    HAS_PYDANTIC = True
except Exception:  # graceful fallback if pydantic/app package unavailable
    NormalizedEvent = None  # type: ignore
    HAS_PYDANTIC = False


ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}

# Accepted collection_type values (canonical names from
# docs/DATA_CONTRACT.md section 10; short aliases accepted).
AUTH_TYPES = {"linux_auth_log", "linux_auth"}
SYSLOG_TYPES = {"linux_syslog", "linux_system_log"}
CRON_TYPES = {"linux_cron"}
SYSTEMD_TYPES = {"linux_systemd_services", "linux_systemd"}
SSH_TYPES = {"linux_ssh_metadata", "linux_ssh"}

# File-name hints used only for stable processing order; the actual
# dispatch always relies on the "collection_type" field inside the data.
_NAME_HINTS = (
    ("auth", 0),
    ("syslog", 1),
    ("cron", 2),
    ("systemd", 3),
    ("ssh", 4),
)

# Friendly per-source "source" values on the normalized event.
_SOURCE_NAMES = {
    "auth": "auth.log",
    "syslog": "syslog",
    "cron": "cron",
    "systemd": "systemd",
    "ssh": "ssh",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _to_contract_timestamp(value: Any) -> str:
    """Convert a datetime/ISO string into the contract format '...Z' (UTC)."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise ValueError("timestamp is not a datetime or ISO string")
    if value.tzinfo is None:
        raise ValueError("timestamp without timezone info (contract requires UTC)")
    value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_event(event: dict) -> dict:
    """Validate one event against the Data Contract; raise ValueError if bad."""
    required = (
        "event_id", "case_id", "host_id", "platform", "event_type",
        "timestamp", "severity", "source", "evidence_reference", "message",
    )
    missing = [key for key in required if not event.get(key)]
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")
    if event["severity"] not in ALLOWED_SEVERITIES:
        raise ValueError(f"invalid severity '{event['severity']}'")
    event["timestamp"] = _to_contract_timestamp(event["timestamp"])
    event.setdefault("metadata", {})

    if HAS_PYDANTIC:
        normalized = NormalizedEvent.model_validate(event).model_dump()
        normalized["timestamp"] = _to_contract_timestamp(normalized["timestamp"])
        return normalized

    # Manual fallback validation (pydantic not installed)
    event = dict(event)
    event["timestamp"] = _to_contract_timestamp(event["timestamp"])
    return event


# ---------------------------------------------------------------------------
# timestamp handling
# ---------------------------------------------------------------------------

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
_SYSLOG_TS_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+"
)


def _collected_base(collected_at: Any) -> datetime | None:
    """Parse the file-level collected_at into an aware UTC datetime."""
    if not collected_at:
        return None
    try:
        value = datetime.fromisoformat(str(collected_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        # collected_at without timezone cannot be trusted as UTC; treat as
        # unusable so the record is rejected instead of silently shifted.
        return None
    return value.astimezone(timezone.utc)


def _event_timestamp(message: str, collected_at: Any) -> datetime:
    """Timestamp for one raw line.

    Syslog-style lines ("Nov  4 10:14:55 ...") carry month/day/time but no
    year or timezone: the year comes from collected_at and the time is
    interpreted as UTC (the collector and contract work in UTC). Lines
    without a syslog prefix (cron files, ssh config) use collected_at.
    """
    base = _collected_base(collected_at)
    match = _SYSLOG_TS_RE.match(message)
    if match and base is not None:
        month = _MONTHS.get(match.group(1))
        if month is None:
            raise ValueError(f"unknown month '{match.group(1)}' in log line")
        day = int(match.group(2))
        hour, minute, second = (int(match.group(i)) for i in (3, 4, 5))
        try:
            return base.replace(
                month=month, day=day, hour=hour, minute=minute, second=second,
            )
        except ValueError as exc:
            raise ValueError(f"invalid syslog date in log line: {exc}") from None
    if base is not None:
        return base
    raise ValueError(
        "no timestamp available (line has no syslog date and file has no "
        "usable collected_at)"
    )


# ---------------------------------------------------------------------------
# per-source normalization
# ---------------------------------------------------------------------------

_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from "
    r"(\d+\.\d+\.\d+\.\d+) port (\d+)"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (password|publickey) for (\S+) from "
    r"(\d+\.\d+\.\d+\.\d+) port (\d+)"
)
_SUDO_RE = re.compile(r"sudo(?:\[\d+\])?:\s+(\S+)\s+:.*?COMMAND=(.*)$")
_USERADD_RE = re.compile(r"useradd\[\d+\]:\s+new user: name=([^,;\s]+)")
_SESSION_OPEN_RE = re.compile(r"session opened for user (\S+)")
_PUBLIC_KEY_RE = re.compile(
    r"^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+)\s+(\S+)(?:\s+(.*))?$"
)
_CRON_SYSLOG_RE = re.compile(r"CRON\[\d+\]:\s+\((\S+)\)\s+CMD\s+\((.*)\)\s*$")


def _extract_sudo_target(command: str) -> str:
    """Best-effort target account from a sudo useradd/usermod command.

    The account name is the last token: 'useradd -m svc_update' ->
    'svc_update'; 'usermod -aG sudo svc_update' -> 'svc_update'.
    """
    tokens = str(command or "").split()
    return tokens[-1] if tokens else ""


def _auth_record_to_event(record: dict, case_id: str, host_id: str,
                          collected_at: Any, event_id: str) -> dict:
    message = str(record.get("message") or "").strip()
    if not message:
        raise ValueError("empty auth log line")
    source_path = str(record.get("source") or "auth.log")
    line_no = record.get("line_no")
    timestamp = _event_timestamp(message, collected_at)

    failed = _FAILED_RE.search(message)
    if failed:
        username, source_ip, port = failed.group(1), failed.group(2), failed.group(3)
        invalid_user = "invalid user" in message
        return _validate_event({
            "event_id": event_id,
            "case_id": case_id,
            "host_id": host_id,
            "platform": "linux",
            "event_type": "failed_login",
            "timestamp": timestamp,
            "severity": "medium",
            "source": "auth.log",
            "evidence_reference": f"{source_path}:line-{line_no}",
            "message": f"Failed password for '{username}' from {source_ip} port {port}",
            "metadata": {
                "username": username,
                "source_ip": source_ip,
                "port": port,
                "auth_method": "password",
                "invalid_user": invalid_user,
                "process": "sshd",
            },
        })

    accepted = _ACCEPTED_RE.search(message)
    if accepted:
        method, username, source_ip, port = accepted.groups()
        return _validate_event({
            "event_id": event_id,
            "case_id": case_id,
            "host_id": host_id,
            "platform": "linux",
            "event_type": "successful_login",
            "timestamp": timestamp,
            "severity": "low",
            "source": "auth.log",
            "evidence_reference": f"{source_path}:line-{line_no}",
            "message": f"Successful {method} login for '{username}' from {source_ip} port {port}",
            "metadata": {
                "username": username,
                "source_ip": source_ip,
                "port": port,
                "auth_method": method,
                "process": "sshd",
            },
        })

    sudo = _SUDO_RE.search(message)
    if sudo:
        actor, command = sudo.group(1), sudo.group(2).strip()
        lowered = command.lower()
        if "useradd" in lowered:
            event_type, severity = "account_created", "high"
        elif "usermod" in lowered and any(
            group in lowered for group in ("sudo", "wheel", "admin")
        ):
            event_type, severity = "account_modified", "high"
        elif "journalctl" in lowered and any(
            flag in lowered for flag in ("vacuum", "rotate")
        ):
            event_type, severity = "audit_log_cleared", "high"
        else:
            event_type, severity = "sudo_command", "medium"
        metadata: dict = {"actor": actor, "command": command}
        if "useradd" in lowered or "usermod" in lowered:
            target = _extract_sudo_target(command)
            if target:
                metadata["target_account"] = target
        return _validate_event({
            "event_id": event_id,
            "case_id": case_id,
            "host_id": host_id,
            "platform": "linux",
            "event_type": event_type,
            "timestamp": timestamp,
            "severity": severity,
            "source": "auth.log",
            "evidence_reference": f"{source_path}:line-{line_no}",
            "message": f"sudo by '{actor}': {command}",
            "metadata": metadata,
        })

    useradd = _USERADD_RE.search(message)
    if useradd:
        username = useradd.group(1)
        return _validate_event({
            "event_id": event_id,
            "case_id": case_id,
            "host_id": host_id,
            "platform": "linux",
            "event_type": "account_created",
            "timestamp": timestamp,
            "severity": "high",
            "source": "auth.log",
            "evidence_reference": f"{source_path}:line-{line_no}",
            "message": f"New user account created: '{username}'",
            "metadata": {"username": username, "process": "useradd"},
        })

    session = _SESSION_OPEN_RE.search(message)
    if session:
        username = session.group(1)
        return _validate_event({
            "event_id": event_id,
            "case_id": case_id,
            "host_id": host_id,
            "platform": "linux",
            "event_type": "session_opened",
            "timestamp": timestamp,
            "severity": "low",
            "source": "auth.log",
            "evidence_reference": f"{source_path}:line-{line_no}",
            "message": f"Session opened for user '{username}'",
            "metadata": {"username": username},
        })

    # Any other auth-log line stays as low-severity context evidence.
    return _validate_event({
        "event_id": event_id,
        "case_id": case_id,
        "host_id": host_id,
        "platform": "linux",
        "event_type": "auth_event",
        "timestamp": timestamp,
        "severity": "low",
        "source": "auth.log",
        "evidence_reference": f"{source_path}:line-{line_no}",
        "message": message[:200],
        "metadata": {},
    })


def _syslog_record_to_event(record: dict, case_id: str, host_id: str,
                            collected_at: Any, event_id: str) -> dict:
    message = str(record.get("message") or "").strip()
    if not message:
        raise ValueError("empty syslog line")
    source_path = str(record.get("source") or "syslog")
    line_no = record.get("line_no")
    timestamp = _event_timestamp(message, collected_at)

    cron_cmd = _CRON_SYSLOG_RE.search(message)
    if cron_cmd:
        user, command = cron_cmd.group(1), cron_cmd.group(2)
        return _validate_event({
            "event_id": event_id,
            "case_id": case_id,
            "host_id": host_id,
            "platform": "linux",
            "event_type": "process_execution",
            "timestamp": timestamp,
            "severity": "low",
            "source": "syslog",
            "evidence_reference": f"{source_path}:line-{line_no}",
            "message": f"Cron executed command for user '{user}': {command}",
            "metadata": {"user": user, "command": command, "process": "cron"},
        })

    return _validate_event({
        "event_id": event_id,
        "case_id": case_id,
        "host_id": host_id,
        "platform": "linux",
        "event_type": "system_log",
        "timestamp": timestamp,
        "severity": "low",
        "source": "syslog",
        "evidence_reference": f"{source_path}:line-{line_no}",
        "message": message[:200],
        "metadata": {},
    })


def _parse_cron_line(message: str) -> dict:
    """Parse one crontab rule line -> {schedule, user, command}.

    System files (/etc/crontab, /etc/cron.d/*) have a user field:
    "m h dom mon dow user command". User crontabs have six fields only:
    "m h dom mon dow command" (the user comes from the file path).
    """
    text = message.strip()
    if not text or text.startswith("#"):
        raise ValueError("cron comment/env line (not a rule) - skipped")
    tokens = text.split()
    if text.startswith("@"):
        parts = text.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"unrecognized cron special line '{text}'")
        return {"schedule": parts[0], "user": "", "command": parts[1]}
    if len(tokens) >= 7:
        return {
            "schedule": " ".join(tokens[:5]),
            "user": tokens[5],
            "command": " ".join(tokens[6:]),
        }
    if len(tokens) == 6:
        return {"schedule": " ".join(tokens[:5]), "user": "", "command": tokens[5]}
    raise ValueError(
        f"unrecognized cron line ({len(tokens)} field(s), expected 6+)"
    )


def _cron_record_to_event(record: dict, case_id: str, host_id: str,
                          collected_at: Any, event_id: str) -> dict:
    message = str(record.get("message") or "").strip()
    if not message:
        raise ValueError("empty cron line")
    source_path = str(record.get("source") or "cron")
    line_no = record.get("line_no")
    fields = _parse_cron_line(message)
    user = fields["user"]
    if not user and "/var/spool/cron" in source_path:
        # User crontab files live at /var/spool/cron/crontabs/<user>;
        # the file name is the account name.
        user = Path(source_path).name
    return _validate_event({
        "event_id": event_id,
        "case_id": case_id,
        "host_id": host_id,
        "platform": "linux",
        "event_type": "cron_modified",
        "timestamp": _event_timestamp(message, collected_at),
        "severity": "low",
        "source": "cron",
        "evidence_reference": f"{source_path}:line-{line_no}",
        "message": f"Cron job ({fields['schedule']}) as '{user or 'unknown'}': "
                   f"{fields['command']}",
        "metadata": {
            "schedule": fields["schedule"],
            "user": user,
            "command": fields["command"],
            "cron_file": source_path,
        },
    })


def _systemd_record_to_event(record: dict, case_id: str, host_id: str,
                             collected_at: Any, event_id: str) -> dict:
    message = str(record.get("message") or "").strip()
    if not message:
        raise ValueError("empty systemd record")
    source_path = str(record.get("source") or "systemd")
    line_no = record.get("line_no")
    # Collector file-scan format: "unit.service: description".
    # systemctl format: "unit.service enabled enabled".
    if ":" in message:
        unit, _, description = message.partition(":")
        unit, description = unit.strip(), description.strip()
    else:
        parts = message.split()
        unit = parts[0] if parts else ""
        description = " ".join(parts[1:])
    if not unit:
        raise ValueError("systemd record without unit name")
    return _validate_event({
        "event_id": event_id,
        "case_id": case_id,
        "host_id": host_id,
        "platform": "linux",
        "event_type": "service_metadata",
        "timestamp": _event_timestamp(message, collected_at),
        "severity": "low",
        "source": "systemd",
        "evidence_reference": f"{source_path}:line-{line_no}",
        "message": f"Systemd unit '{unit}': {description or '(no description)'}",
        "metadata": {
            "unit": unit,
            "description": description,
            "service_file": source_path,
        },
    })


def _ssh_record_to_event(record: dict, case_id: str, host_id: str,
                         collected_at: Any, event_id: str) -> dict:
    message = str(record.get("message") or "").strip()
    if not message:
        raise ValueError("empty ssh metadata line")
    source_path = str(record.get("source") or "ssh")
    line_no = record.get("line_no")
    timestamp = _event_timestamp(message, collected_at)
    evidence = f"{source_path}:line-{line_no}"

    public_key = _PUBLIC_KEY_RE.match(message)
    if public_key:
        key_type, material, comment = (
            public_key.group(1), public_key.group(3), public_key.group(4) or "",
        )
        return _validate_event({
            "event_id": event_id,
            "case_id": case_id,
            "host_id": host_id,
            "platform": "linux",
            "event_type": "ssh_key_modified",
            "timestamp": timestamp,
            "severity": "low",
            "source": "ssh",
            "evidence_reference": evidence,
            "message": f"Authorized {key_type} key present"
                       f"{' for ' + comment if comment else ''}",
            "metadata": {
                "key_type": key_type,
                "key_data": material,
                "comment": comment,
                "ssh_file": source_path,
            },
        })

    if message.startswith("#"):
        raise ValueError("sshd_config comment line - skipped")
    config = re.match(r"^([A-Za-z]\S*)\s+(.+)$", message)
    if config:
        option, value = config.group(1), config.group(2).strip()
        return _validate_event({
            "event_id": event_id,
            "case_id": case_id,
            "host_id": host_id,
            "platform": "linux",
            "event_type": "ssh_config_event",
            "timestamp": timestamp,
            "severity": "low",
            "source": "ssh",
            "evidence_reference": evidence,
            "message": f"sshd_config: {option} {value}",
            "metadata": {"option": option, "value": value,
                         "config_file": source_path},
        })
    raise ValueError(f"unrecognized ssh metadata line: {message[:60]}")


# ---------------------------------------------------------------------------
# file / directory drivers
# ---------------------------------------------------------------------------

_TYPE_DISPATCH = (
    (AUTH_TYPES, "auth"),
    (SYSLOG_TYPES, "syslog"),
    (CRON_TYPES, "cron"),
    (SYSTEMD_TYPES, "systemd"),
    (SSH_TYPES, "ssh"),
)
_RECORD_HANDLERS = {
    "auth": _auth_record_to_event,
    "syslog": _syslog_record_to_event,
    "cron": _cron_record_to_event,
    "systemd": _systemd_record_to_event,
    "ssh": _ssh_record_to_event,
}


def _normalize_record(location: str, kind: str, raw: dict,
                      case_id: str, counter: int, host_id: str,
                      collected_at: Any) -> tuple[dict | None, str | None]:
    """Return (event, error_reason). Exactly one of the two is set."""
    try:
        if kind == "__error__":
            raise ValueError(str(raw.get("__error__") or "unparsable record"))
        if not host_id:
            raise ValueError("missing host_id in collector file")
        handler = _RECORD_HANDLERS[kind]
        event = handler(raw, case_id, host_id, collected_at,
                        f"evt-lin-{counter:06d}")
        return event, None
    except (ValueError, TypeError) as exc:
        return None, f"{location}: {exc}"


def _file_sort_key(path: Path) -> tuple:
    name = path.name.lower()
    for prefix, order in _NAME_HINTS:
        if prefix in name:
            return (order, name)
    return (9, name)


def parse_file(path: Path, case_id: str, start_index: int = 1
               ) -> tuple[list[dict], list[str]]:
    """Parse one collector JSON file; returns (events, warnings)."""
    events: list[dict] = []
    warnings: list[str] = []
    counter = start_index

    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return [], [f"{path.name}: invalid JSON ({exc.msg})"]
    if not isinstance(obj, dict):
        return [], [f"{path.name}: expected a JSON object from the collector"]

    if path.name == "collection_summary.json":
        return [], [f"{path.name}: collection summary skipped (not evidence)"]

    ctype = str(obj.get("collection_type") or "__unknown__")
    kind = "__unknown__"
    for types, candidate in _TYPE_DISPATCH:
        if ctype in types:
            kind = candidate
            break

    host_id = str(obj.get("host_id") or "").strip()
    collected_at = obj.get("collected_at")
    status = str(obj.get("status") or "")
    records = obj.get("records")

    if kind == "__unknown__":
        warnings.append(
            f"{path.name}: unsupported collection_type '{ctype}' - skipped")
        return events, warnings
    if not isinstance(records, list) or not records:
        if status and status != "collected":
            warnings.append(
                f"{path.name}: source status '{status}' with no records - "
                f"nothing to parse")
        else:
            warnings.append(f"{path.name}: no records found - nothing to parse")
        return events, warnings

    for index, record in enumerate(records, start=1):
        location = f"{path.name}:record-{index}"
        if not isinstance(record, dict):
            warnings.append(f"{location}: record is not an object")
            continue
        event, reason = _normalize_record(
            location, kind, record, case_id, counter, host_id, collected_at)
        if event is None:
            warnings.append(reason or f"{location}: unknown error")
            continue
        events.append(event)
        counter += 1
    return events, warnings


def parse_directory(directory: str | Path, case_id: str = "case-000001"
                    ) -> tuple[list[dict], list[str]]:
    """Parse every raw Linux collector file inside a directory (stable order)."""
    directory = Path(directory)
    warnings: list[str] = []
    if not directory.exists():
        warnings.append(f"input directory not found: {directory}")
        return [], warnings
    if not directory.is_dir():
        warnings.append(f"input path is not a directory: {directory}")
        return [], warnings

    files = sorted(
        (p for p in directory.iterdir() if p.is_file()
         and p.suffix.lower() == ".json"),
        key=_file_sort_key,
    )
    if not files:
        warnings.append(f"no .json collector files found in: {directory}")
        return [], warnings

    events: list[dict] = []
    counter = 1
    for path in files:
        file_events, file_warnings = parse_file(path, case_id, start_index=counter)
        events.extend(file_events)
        warnings.extend(file_warnings)
        counter += len(file_events) + 1
    # Renumber sequentially (counters above may leave gaps after skips)
    for index, event in enumerate(events, start=1):
        event["event_id"] = f"evt-lin-{index:06d}"
    return events, warnings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    arg_parser = argparse.ArgumentParser(
        description="Parse raw Linux collector evidence into NormalizedEvents "
                    "(DFIR Data Contract).")
    arg_parser.add_argument("--input", default="sample_data/linux",
                            help="directory with collector output "
                                 "(default: sample_data/linux)")
    arg_parser.add_argument("--out", default="output/linux/events.jsonl",
                            help="output JSONL path "
                                 "(default: output/linux/events.jsonl)")
    arg_parser.add_argument("--case-id", default="case-000001",
                            help="investigation case id (default: case-000001)")
    args = arg_parser.parse_args(argv)

    events, warnings = parse_directory(args.input, case_id=args.case_id)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"[parser] input     : {args.input}")
    print(f"[parser] events    : {len(events)} NormalizedEvents written")
    print(f"[parser] skipped   : {len(warnings)} records")
    print(f"[parser] output    : {out_path}")
    for warning in warnings[:20]:
        print(f"[parser] WARNING   : {warning}")
    if len(warnings) > 20:
        print(f"[parser] WARNING   : ... and {len(warnings) - 20} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
