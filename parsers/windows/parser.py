"""
Windows Parser — raw collected evidence -> NormalizedEvent (DFIR Data Contract).

Input files (produced by collectors/windows/collector.ps1, or provided as
sanitized samples under sample_data/windows/):

    security_events.jsonl   (collection_type: windows_security_event)
    scheduled_tasks.json    (collection_type: windows_scheduled_tasks)
    services.json           (collection_type: windows_services)
    registry_runkeys.json   (collection_type: windows_registry_runkeys)

Output: a JSONL file where every line is a validated NormalizedEvent dict
matching docs/DATA_CONTRACT.md.

Design rules (per the team guides):
    - Unparsable or incomplete records are logged and skipped, never crash.
    - Missing fields are never invented.
    - Timestamps must be UTC ISO 8601 ("...Z"); local naive timestamps are
      rejected.
    - Every event carries an evidence_reference back to the raw evidence.

Usage:
    python parsers/windows/parser.py --input sample_data/windows \
        --out output/windows/events.jsonl --case-id case-000001
"""

from __future__ import annotations

import argparse
import json
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

# Windows Security event IDs -> (normalized event_type, default severity)
SUPPORTED_SECURITY_EVENT_IDS = {
    4624: ("successful_login", "low"),
    4625: ("failed_login", "medium"),
    4720: ("account_created", "high"),
    4732: ("account_modified", "medium"),
    1102: ("audit_log_cleared", "high"),
}

# File-name hints used only for stable processing order; the actual
# dispatch always relies on the "collection_type" field inside the data.
_NAME_HINTS = (
    ("security", 0),
    ("scheduled", 1),
    ("service", 2),
    ("registry", 3),
    ("runkey", 3),
)


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


def _strip_bom(line: str) -> str:
    return line.lstrip("\ufeff").strip()


# ---------------------------------------------------------------------------
# per-source normalization
# ---------------------------------------------------------------------------

def _security_event_to_event(raw: dict, case_id: str, event_id: str) -> dict:
    event_code = raw.get("event_id")
    try:
        event_code = int(event_code)
    except (TypeError, ValueError):
        raise ValueError(f"invalid event_id '{event_code}'") from None
    if event_code not in SUPPORTED_SECURITY_EVENT_IDS:
        raise ValueError(f"unsupported windows security event id {event_code}")

    event_type, severity = SUPPORTED_SECURITY_EVENT_IDS[event_code]
    data = raw.get("data") or {}
    host_id = str(raw.get("host_id") or "").strip()
    if not host_id:
        raise ValueError("missing host_id")

    username = data.get("target_username") or data.get("username") or ""
    subject = data.get("subject_username") or ""
    source_ip = data.get("source_ip") or ""
    logon_type = data.get("logon_type")
    group_name = data.get("group_name") or ""

    metadata: dict = {"original_event_id": event_code}
    message = ""

    if event_code in (4624, 4625):
        metadata.update({
            "username": username,
            "source_ip": source_ip,
            "logon_type": logon_type,
        })
        if data.get("workstation_name"):
            metadata["workstation_name"] = data["workstation_name"]
        if event_code == 4625 and data.get("status"):
            metadata["status_code"] = data["status"]
        verb = "Successful" if event_code == 4624 else "Failed"
        message = f"{verb} logon for user '{username}' from {source_ip or 'unknown'}"
    elif event_code == 4720:
        metadata.update({"username": username, "subject_username": subject})
        message = f"Account created: '{username}' (by {subject or 'unknown'})"
    elif event_code == 4732:
        metadata.update({
            "username": username,
            "group_name": group_name,
            "subject_username": subject,
        })
        if "admin" in group_name.lower():
            severity = "high"
        message = f"User '{username}' added to group '{group_name or 'unknown'}'"
    elif event_code == 1102:
        metadata.update({"subject_username": subject})
        message = f"Security audit log cleared (by {subject or 'unknown'})"

    record_id = raw.get("record_id")
    return _validate_event({
        "event_id": event_id,
        "case_id": case_id,
        "host_id": host_id,
        "platform": "windows",
        "event_type": event_type,
        "timestamp": raw.get("timestamp"),
        "severity": severity,
        "source": "security.evtx",
        "evidence_reference": f"security.evtx:record-{record_id if record_id else 'unknown'}",
        "message": message,
        "metadata": metadata,
    })


def _task_item_to_event(item: dict, case_id: str, host_id: str, event_id: str) -> dict:
    name = str(item.get("name") or "").strip()
    if not name:
        raise ValueError("scheduled task without name")
    actions = item.get("actions") or []
    first = actions[0] if actions else {}
    execute = str(first.get("execute") or "")
    arguments = str(first.get("arguments") or "")
    return _validate_event({
        "event_id": event_id,
        "case_id": case_id,
        "host_id": host_id,
        "platform": "windows",
        "event_type": "scheduled_task_created",
        "timestamp": item.get("collected_at") or item.get("timestamp"),
        "severity": "low",
        "source": "Scheduled Tasks",
        "evidence_reference": f"Tasks\\{name}",
        "message": f"Scheduled task '{name}' -> {execute or '(no action)'}",
        "metadata": {
            "task_name": name,
            "task_path": item.get("path") or "",
            "author": item.get("author") or "",
            "status": item.get("status") or "",
            "run_as": item.get("run_as") or "",
            "action_execute": execute,
            "action_arguments": arguments,
        },
    })


def _service_item_to_event(item: dict, case_id: str, host_id: str, event_id: str) -> dict:
    name = str(item.get("name") or "").strip()
    if not name:
        raise ValueError("service without name")
    binary_path = str(item.get("binary_path") or "")
    status = str(item.get("status") or "")
    return _validate_event({
        "event_id": event_id,
        "case_id": case_id,
        "host_id": host_id,
        "platform": "windows",
        "event_type": "service_created",
        "timestamp": item.get("collected_at") or item.get("timestamp"),
        "severity": "low",
        "source": "Services",
        "evidence_reference": f"Services\\{name}",
        "message": f"Service '{name}' [{status}] -> {binary_path or '(no path)'}",
        "metadata": {
            "service_name": name,
            "display_name": item.get("display_name") or "",
            "status": status,
            "start_type": item.get("start_type") or "",
            "account": item.get("account") or "",
            "binary_path": binary_path,
        },
    })


def _runkey_item_to_event(item: dict, case_id: str, host_id: str, event_id: str) -> dict:
    hive = str(item.get("hive") or "").strip()
    key = str(item.get("key") or "").strip()
    value_name = str(item.get("value_name") or "").strip()
    command = str(item.get("command") or "")
    if not (hive and key and value_name):
        raise ValueError("run key entry missing hive/key/value_name")
    reference = f"{hive}\\{key}:{value_name}"
    return _validate_event({
        "event_id": event_id,
        "case_id": case_id,
        "host_id": host_id,
        "platform": "windows",
        "event_type": "persistence_detected",
        "timestamp": item.get("collected_at") or item.get("timestamp"),
        "severity": "medium",
        "source": "Registry Run Keys",
        "evidence_reference": reference,
        "message": f"Registry Run key entry '{reference}' -> {command or '(no command)'}",
        "metadata": {
            "hive": hive,
            "key": key,
            "value_name": value_name,
            "command": command,
        },
    })


# ---------------------------------------------------------------------------
# file / directory drivers
# ---------------------------------------------------------------------------

def _read_records(path: Path) -> list[tuple[str, str, dict]]:
    """Yield (location, collection_type, raw_record) triples from one file."""
    records: list[tuple[str, str, dict]] = []
    text = path.read_text(encoding="utf-8", errors="replace")

    if path.suffix.lower() == ".jsonl":
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = _strip_bom(line)
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                records.append((f"{path.name}:line-{line_no}", "__error__", {
                    "__error__": f"invalid JSON ({exc.msg})",
                }))
                continue
            records.append((f"{path.name}:line-{line_no}",
                            str(obj.get("collection_type") or "__unknown__"), obj))
    else:
        location = path.name
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            records.append((location, "__error__", {
                "__error__": f"invalid JSON ({exc.msg})",
            }))
            return records
        ctype = str(obj.get("collection_type") or "__unknown__")
        items = obj.get("items")
        if isinstance(items, list):
            host_id = obj.get("host_id") or ""
            collected_at = obj.get("collected_at") or ""
            for index, item in enumerate(items, start=1):
                if isinstance(item, dict):
                    item.setdefault("host_id", host_id)
                    item.setdefault("collected_at", collected_at)
                    records.append((f"{location}:item-{index}", ctype, item))
                else:
                    records.append((f"{location}:item-{index}", "__error__",
                                    {"__error__": "item is not an object"}))
        else:
            records.append((location, ctype, obj))
    return records


def _normalize_record(location: str, ctype: str, raw: dict,
                      case_id: str, counter: int,
                      default_host: str) -> tuple[dict | None, str | None]:
    """Return (event, error_reason). Exactly one of the two is set."""
    try:
        if ctype == "__error__":
            raise ValueError(str(raw.get("__error__") or "unparsable record"))
        host_id = str(raw.get("host_id") or default_host or "").strip()
        if ctype == "windows_security_event":
            event = _security_event_to_event(raw, case_id, f"evt-win-{counter:06d}")
        elif ctype == "windows_scheduled_tasks":
            event = _task_item_to_event(raw, case_id, host_id, f"evt-win-{counter:06d}")
        elif ctype == "windows_services":
            event = _service_item_to_event(raw, case_id, host_id, f"evt-win-{counter:06d}")
        elif ctype == "windows_registry_runkeys":
            event = _runkey_item_to_event(raw, case_id, host_id, f"evt-win-{counter:06d}")
        elif ctype == "__unknown__":
            raise ValueError("missing collection_type")
        else:
            raise ValueError(f"unsupported collection_type '{ctype}'")
        return event, None
    except (ValueError, TypeError) as exc:
        return None, f"{location}: {exc}"


def _file_sort_key(path: Path) -> tuple:
    name = path.name.lower()
    for prefix, order in _NAME_HINTS:
        if name.startswith(prefix):
            return (order, name)
    return (9, name)


def parse_file(path: Path, case_id: str, start_index: int = 1
               ) -> tuple[list[dict], list[str]]:
    """Parse one raw file; returns (events, warnings). Never raises on bad data."""
    events: list[dict] = []
    warnings: list[str] = []
    counter = start_index
    for location, ctype, raw in _read_records(path):
        event, reason = _normalize_record(location, ctype, raw, case_id, counter, "")
        if event is None:
            warnings.append(reason or f"{location}: unknown error")
            continue
        events.append(event)
        counter += 1
    return events, warnings


def parse_directory(directory: str | Path, case_id: str = "case-000001"
                    ) -> tuple[list[dict], list[str]]:
    """Parse every raw Windows file inside a directory (stable order)."""
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
         and p.suffix.lower() in {".jsonl", ".json"}),
        key=_file_sort_key,
    )
    if not files:
        warnings.append(f"no .json/.jsonl input files found in: {directory}")
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
        event["event_id"] = f"evt-win-{index:06d}"
    return events, warnings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    arg_parser = argparse.ArgumentParser(
        description="Parse raw Windows evidence into NormalizedEvents "
                    "(DFIR Data Contract).")
    arg_parser.add_argument("--input", default="sample_data/windows",
                            help="directory with raw collector output "
                                 "(default: sample_data/windows)")
    arg_parser.add_argument("--out", default="output/windows/events.jsonl",
                            help="output JSONL path (default: output/windows/events.jsonl)")
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
