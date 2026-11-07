"""
Windows Detection Rules — NormalizedEvents -> NormalizedFindings + IOCs.

Rule IDs implemented here (all produce *potential* findings with
status="unverified" that require analyst review — never a final verdict):

    WIN-AUTH-001  Repeated failed logons from the same source IP
                  within a time window (possible brute force).
    WIN-AUTH-002  Successful logon from the same IP that just produced
                  failed logons (possible successful brute force).
    WIN-PERS-001  Scheduled task executing from a user-writable path.
    WIN-PERS-002  Registry Run key pointing to a user-writable path.
    WIN-PERS-003  Windows service binary located in a user-writable path.

Usage:
    from detection.windows import rules
    findings, iocs = rules.run_detection(events, case_id="case-000001")
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

# Paths that regular users can write to — anything executing from here
# that claims to be system software is suspicious (MITRE ATT&CK defense
# evasion / persistence patterns). Compared case-insensitively.
SUSPICIOUS_PATH_MARKERS = (
    "\\windows\\temp\\",
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
)

BRUTE_FORCE_WINDOW_MINUTES = 10
BRUTE_FORCE_THRESHOLD = 3
SUCCESS_AFTER_FAILURE_WINDOW_MINUTES = 30


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _is_suspicious_path(path: str) -> bool:
    normalized = str(path or "").replace("/", "\\").lower()
    return any(marker in normalized for marker in SUSPICIOUS_PATH_MARKERS)


def _extract_exe_from_command(command: str) -> str:
    """Best-effort extraction of an executable path from a command line."""
    text = str(command or "").strip()
    if not text:
        return ""
    if text.startswith('"'):
        return text.split('"', 2)[1] if '"' in text[1:] else text
    for separator in (" -", " /"):
        if separator in text:
            text = text.split(separator, 1)[0]
    return text.strip()


class _Emitter:
    """Collects findings and IOCs with sequential contract-style ids."""

    def __init__(self) -> None:
        self.findings: list[dict] = []
        self.iocs: list[dict] = []
        self._finding_no = 0
        self._ioc_no = 0
        self._seen_iocs: set[tuple[str, str]] = set()

    def add_finding(self, *, case_id: str, host_id: str, title: str,
                    description: str, severity: str, rule_id: str,
                    evidence_reference: str, mitre_technique: str | None,
                    extra_evidence: list[str] | None = None) -> None:
        self._finding_no += 1
        self.findings.append({
            "finding_id": f"finding-{self._finding_no:06d}",
            "case_id": case_id,
            "host_id": host_id,
            "platform": "windows",
            "title": title,
            "description": description,
            "severity": severity,
            "rule_id": rule_id,
            "status": "unverified",
            "evidence_reference": evidence_reference,
            "mitre_technique": mitre_technique,
            "related_evidence": extra_evidence or [],
        })

    def add_ioc(self, *, case_id: str, host_id: str, ioc_type: str,
                value: str, source: str, evidence_reference: str,
                confidence: str) -> None:
        key = (ioc_type, str(value).lower())
        if not value or key in self._seen_iocs:
            return
        self._seen_iocs.add(key)
        self._ioc_no += 1
        self.iocs.append({
            "ioc_id": f"ioc-{self._ioc_no:06d}",
            "case_id": case_id,
            "host_id": host_id,
            "ioc_type": ioc_type,
            "value": value,
            "source": source,
            "evidence_reference": evidence_reference,
            "confidence": confidence,
        })


# ---------------------------------------------------------------------------
# rule 1: WIN-AUTH-001 repeated failed logons (brute force)
# ---------------------------------------------------------------------------

def _detect_brute_force(events: list[dict], emitter: _Emitter) -> None:
    groups: dict[str, list[dict]] = {}
    for event in events:
        if event.get("event_type") != "failed_login":
            continue
        ip = str((event.get("metadata") or {}).get("source_ip") or "").strip()
        if not ip or ip in ("-", "?"):
            continue
        groups.setdefault(ip, []).append(event)

    for ip, fails in groups.items():
        fails.sort(key=lambda e: e["timestamp"])
        times = [_parse_ts(e["timestamp"]) for e in fails]
        window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        burst: list[dict] = []
        for index in range(len(fails) - BRUTE_FORCE_THRESHOLD + 1):
            span = times[index + BRUTE_FORCE_THRESHOLD - 1] - times[index]
            if span <= window:
                burst = fails[index:index + BRUTE_FORCE_THRESHOLD]
                break
        if not burst:
            continue

        usernames = sorted({(e.get("metadata") or {}).get("username", "")
                            for e in fails})
        evidence_refs = [e["evidence_reference"] for e in burst]
        emitter.add_finding(
            case_id=fails[0]["case_id"],
            host_id=fails[0]["host_id"],
            title="Repeated failed logons from one source IP",
            description=(
                f"{len(fails)} failed logon events were recorded from IP "
                f"{ip} targeting user account(s): "
                f"{', '.join(u for u in usernames if u) or 'unknown'}. At "
                f"least {BRUTE_FORCE_THRESHOLD} attempts occurred within "
                f"{BRUTE_FORCE_WINDOW_MINUTES} minutes. This pattern is "
                f"consistent with a password-guessing attempt and requires "
                f"analyst review."),
            severity="medium",
            rule_id="WIN-AUTH-001",
            evidence_reference=evidence_refs[0],
            mitre_technique="T1110",
            extra_evidence=evidence_refs,
        )
        emitter.add_ioc(
            case_id=fails[0]["case_id"],
            host_id=fails[0]["host_id"],
            ioc_type="ip_address",
            value=ip,
            source=fails[0]["source"],
            evidence_reference=evidence_refs[0],
            confidence="medium",
        )


# ---------------------------------------------------------------------------
# rule 2: WIN-AUTH-002 successful logon after failures from the same IP
# ---------------------------------------------------------------------------

def _detect_success_after_failures(events: list[dict], emitter: _Emitter) -> None:
    fails_by_ip: dict[str, list[dict]] = {}
    for event in events:
        if event.get("event_type") != "failed_login":
            continue
        ip = str((event.get("metadata") or {}).get("source_ip") or "").strip()
        if ip:
            fails_by_ip.setdefault(ip, []).append(event)

    for event in events:
        if event.get("event_type") != "successful_login":
            continue
        ip = str((event.get("metadata") or {}).get("source_ip") or "").strip()
        if not ip or ip not in fails_by_ip:
            continue
        success_time = _parse_ts(event["timestamp"])
        window = timedelta(minutes=SUCCESS_AFTER_FAILURE_WINDOW_MINUTES)
        related = [
            fail for fail in fails_by_ip[ip]
            if 0 <= (success_time - _parse_ts(fail["timestamp"])).total_seconds()
            <= window.total_seconds()
        ]
        if not related:
            continue

        username = (event.get("metadata") or {}).get("username", "")
        emitter.add_finding(
            case_id=event["case_id"],
            host_id=event["host_id"],
            title="Successful logon from an IP with recent failed logons",
            description=(
                f"A successful logon for user '{username}' occurred from IP "
                f"{ip} at {event['timestamp']} after {len(related)} failed "
                f"logon attempt(s) from the same IP within "
                f"{SUCCESS_AFTER_FAILURE_WINDOW_MINUTES} minutes. This may "
                f"indicate that a brute-force attempt succeeded and needs "
                f"urgent analyst review."),
            severity="high",
            rule_id="WIN-AUTH-002",
            evidence_reference=event["evidence_reference"],
            mitre_technique="T1078",
            extra_evidence=[fail["evidence_reference"] for fail in related],
        )
        emitter.add_ioc(
            case_id=event["case_id"],
            host_id=event["host_id"],
            ioc_type="username",
            value=username,
            source=event["source"],
            evidence_reference=event["evidence_reference"],
            confidence="low",
        )


# ---------------------------------------------------------------------------
# rule 3: WIN-PERS-001 scheduled task from user-writable path
# ---------------------------------------------------------------------------

def _detect_suspicious_tasks(events: list[dict], emitter: _Emitter) -> None:
    for event in events:
        if event.get("event_type") != "scheduled_task_created":
            continue
        metadata = event.get("metadata") or {}
        execute = str(metadata.get("action_execute") or "")
        if not _is_suspicious_path(execute):
            continue
        task_name = str(metadata.get("task_name") or "")
        run_as = str(metadata.get("run_as") or "unknown")
        emitter.add_finding(
            case_id=event["case_id"],
            host_id=event["host_id"],
            title="Scheduled task executes from a user-writable path",
            description=(
                f"Scheduled task '{task_name}' is configured to execute "
                f"'{execute}' (run as: {run_as}). The binary location is "
                f"user-writable, which is a common scheduled-task "
                f"persistence pattern. The task may be legitimate test "
                f"activity and requires analyst review."),
            severity="high",
            rule_id="WIN-PERS-001",
            evidence_reference=event["evidence_reference"],
            mitre_technique="T1053.005",
        )
        emitter.add_ioc(
            case_id=event["case_id"],
            host_id=event["host_id"],
            ioc_type="scheduled_task",
            value=task_name,
            source=event["source"],
            evidence_reference=event["evidence_reference"],
            confidence="medium",
        )
        emitter.add_ioc(
            case_id=event["case_id"],
            host_id=event["host_id"],
            ioc_type="file_path",
            value=execute,
            source=event["source"],
            evidence_reference=event["evidence_reference"],
            confidence="high",
        )


# ---------------------------------------------------------------------------
# rule 4: WIN-PERS-002 registry Run key to user-writable path
# ---------------------------------------------------------------------------

def _detect_suspicious_run_keys(events: list[dict], emitter: _Emitter) -> None:
    for event in events:
        if event.get("event_type") != "persistence_detected":
            continue
        metadata = event.get("metadata") or {}
        command = str(metadata.get("command") or "")
        executable = _extract_exe_from_command(command)
        if not _is_suspicious_path(executable) and not _is_suspicious_path(command):
            continue
        value_name = str(metadata.get("value_name") or "")
        hive = str(metadata.get("hive") or "")
        key = str(metadata.get("key") or "")
        full_key = f"{hive}\\{key}\\{value_name}"
        emitter.add_finding(
            case_id=event["case_id"],
            host_id=event["host_id"],
            title="Registry Run key launches a binary from a user-writable path",
            description=(
                f"Registry Run value '{value_name}' under {hive}\\{key} "
                f"executes '{command}'. The target location is "
                f"user-writable, a common registry persistence pattern "
                f"(MITRE T1547.001). Requires analyst review."),
            severity="high",
            rule_id="WIN-PERS-002",
            evidence_reference=event["evidence_reference"],
            mitre_technique="T1547.001",
        )
        emitter.add_ioc(
            case_id=event["case_id"],
            host_id=event["host_id"],
            ioc_type="registry_key",
            value=full_key,
            source=event["source"],
            evidence_reference=event["evidence_reference"],
            confidence="medium",
        )
        if executable:
            emitter.add_ioc(
                case_id=event["case_id"],
                host_id=event["host_id"],
                ioc_type="file_path",
                value=executable,
                source=event["source"],
                evidence_reference=event["evidence_reference"],
                confidence="high",
            )


# ---------------------------------------------------------------------------
# rule 5: WIN-PERS-003 service binary in user-writable path
# ---------------------------------------------------------------------------

def _detect_suspicious_services(events: list[dict], emitter: _Emitter) -> None:
    for event in events:
        if event.get("event_type") != "service_created":
            continue
        metadata = event.get("metadata") or {}
        binary_path = str(metadata.get("binary_path") or "")
        if not _is_suspicious_path(binary_path):
            continue
        service_name = str(metadata.get("service_name") or "")
        emitter.add_finding(
            case_id=event["case_id"],
            host_id=event["host_id"],
            title="Windows service binary located in a user-writable path",
            description=(
                f"Service '{service_name}' points to '{binary_path}'. "
                f"Services running from user-writable locations are a "
                f"known service-based persistence pattern (MITRE "
                f"T1543.003). Requires analyst review."),
            severity="high",
            rule_id="WIN-PERS-003",
            evidence_reference=event["evidence_reference"],
            mitre_technique="T1543.003",
        )
        emitter.add_ioc(
            case_id=event["case_id"],
            host_id=event["host_id"],
            ioc_type="service_name",
            value=service_name,
            source=event["source"],
            evidence_reference=event["evidence_reference"],
            confidence="medium",
        )
        emitter.add_ioc(
            case_id=event["case_id"],
            host_id=event["host_id"],
            ioc_type="file_path",
            value=binary_path,
            source=event["source"],
            evidence_reference=event["evidence_reference"],
            confidence="high",
        )


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def run_detection(events: list[dict], case_id: str | None = None
                  ) -> tuple[list[dict], list[dict]]:
    """
    Run all Windows detection rules over a list of NormalizedEvent dicts.

    Returns (findings, iocs). Every finding has status="unverified" and a
    concrete evidence_reference; all outputs follow docs/DATA_CONTRACT.md.
    """
    if case_id is None:
        case_id = events[0]["case_id"] if events else "case-000001"
    # Keep the caller's case_id consistent across all outputs.
    normalized_events = []
    for event in events:
        event = dict(event)
        event["case_id"] = case_id
        normalized_events.append(event)

    emitter = _Emitter()
    _detect_brute_force(normalized_events, emitter)
    _detect_success_after_failures(normalized_events, emitter)
    _detect_suspicious_tasks(normalized_events, emitter)
    _detect_suspicious_run_keys(normalized_events, emitter)
    _detect_suspicious_services(normalized_events, emitter)
    return emitter.findings, emitter.iocs
