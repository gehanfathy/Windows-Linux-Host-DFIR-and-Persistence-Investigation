"""
Linux Detection Rules — NormalizedEvents -> NormalizedFindings + IOCs.

Rule IDs implemented here (all produce *potential* findings with
status="unverified" that require analyst review — never a final verdict):

    LINUX-AUTH-001  Repeated failed logons from the same source IP
                    within a time window (possible SSH brute force).
    LINUX-AUTH-002  Successful login from the same IP that just produced
                    failed logons (possible successful brute force).
    LINUX-PERS-001  Cron job executing from a user-writable path or
                    downloading content (cron persistence).
    LINUX-PERS-002  Authorized SSH key configured for root
                    (SSH-key persistence on a privileged account).

Usage:
    from detection.linux import rules
    findings, iocs = rules.run_detection(events, case_id="case-000001")
"""

from __future__ import annotations

from datetime import datetime, timedelta

# Paths that regular users can write to — anything executed from here by
# cron is a common persistence pattern (MITRE ATT&CK T1053.003).
HIGH_RISK_PATH_MARKERS = ("/tmp/", "/var/tmp/", "/dev/shm/")
MEDIUM_RISK_PATH_MARKERS = ("/home/", "/root/")
DOWNLOAD_MARKERS = ("wget ", "wget\t", "curl ", "curl\t")

BRUTE_FORCE_WINDOW_MINUTES = 10
BRUTE_FORCE_THRESHOLD = 3
SUCCESS_AFTER_FAILURE_WINDOW_MINUTES = 30


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _cron_command_risk(command: str) -> str | None:
    """Classify a cron command: 'high', 'medium', or None if not suspicious."""
    lowered = str(command or "").lower()
    if not lowered:
        return None
    if any(marker in lowered for marker in DOWNLOAD_MARKERS):
        return "high"
    if any(marker in lowered for marker in HIGH_RISK_PATH_MARKERS):
        return "high"
    if any(marker in lowered for marker in MEDIUM_RISK_PATH_MARKERS):
        return "medium"
    return None


def _extract_path_from_command(command: str) -> str:
    """First token of a cron command that looks like a path (contains '/')."""
    for token in str(command or "").split():
        if "/" in token:
            return token
    return ""


class _Emitter:
    """Collects findings and IOCs with sequential contract-style ids."""

    def __init__(self, platform: str = "linux") -> None:
        self.findings: list[dict] = []
        self.iocs: list[dict] = []
        self._finding_no = 0
        self._ioc_no = 0
        self._seen_iocs: set[tuple[str, str]] = set()
        self._platform = platform

    def add_finding(self, *, case_id: str, host_id: str, title: str,
                    description: str, severity: str, rule_id: str,
                    evidence_reference: str, mitre_technique: str | None,
                    extra_evidence: list[str] | None = None) -> None:
        self._finding_no += 1
        self.findings.append({
            "finding_id": f"finding-{self._finding_no:06d}",
            "case_id": case_id,
            "host_id": host_id,
            "platform": self._platform,
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
# rule 1: LINUX-AUTH-001 repeated failed logons (brute force)
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
                f"{len(fails)} failed password attempts were recorded in "
                f"the auth log from IP {ip} targeting user account(s): "
                f"{', '.join(u for u in usernames if u) or 'unknown'}. At "
                f"least {BRUTE_FORCE_THRESHOLD} attempts occurred within "
                f"{BRUTE_FORCE_WINDOW_MINUTES} minutes. This pattern is "
                f"consistent with an SSH password-guessing attempt and "
                f"requires analyst review."),
            severity="medium",
            rule_id="LINUX-AUTH-001",
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
# rule 2: LINUX-AUTH-002 successful login after failures from the same IP
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
            title="Successful login from an IP with recent failed logons",
            description=(
                f"A successful login for user '{username}' occurred from IP "
                f"{ip} at {event['timestamp']} after {len(related)} failed "
                f"logon attempt(s) from the same IP within "
                f"{SUCCESS_AFTER_FAILURE_WINDOW_MINUTES} minutes. This may "
                f"indicate that a brute-force attempt succeeded and needs "
                f"urgent analyst review."),
            severity="high",
            rule_id="LINUX-AUTH-002",
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
# rule 3: LINUX-PERS-001 cron job from user-writable path / downloads
# ---------------------------------------------------------------------------

def _detect_suspicious_cron_jobs(events: list[dict], emitter: _Emitter) -> None:
    for event in events:
        if event.get("event_type") != "cron_modified":
            continue
        metadata = event.get("metadata") or {}
        command = str(metadata.get("command") or "")
        risk = _cron_command_risk(command)
        if risk is None:
            continue
        schedule = str(metadata.get("schedule") or "")
        user = str(metadata.get("user") or "unknown")
        cron_file = str(metadata.get("cron_file") or "unknown file")
        executable = _extract_path_from_command(command)
        reason = {
            "high": ("executes from a world-writable location or downloads "
                     "content"),
            "medium": "executes from a user-writable home/root path",
        }[risk]
        emitter.add_finding(
            case_id=event["case_id"],
            host_id=event["host_id"],
            title="Cron job executes from a user-writable path",
            description=(
                f"Cron job in {cron_file} (schedule: {schedule}, user: "
                f"{user}) runs '{command}'. The command {reason}, which is "
                f"a common cron persistence pattern (MITRE T1053.003). The "
                f"job may be legitimate test activity and requires analyst "
                f"review."),
            severity=risk,
            rule_id="LINUX-PERS-001",
            evidence_reference=event["evidence_reference"],
            mitre_technique="T1053.003",
        )
        emitter.add_ioc(
            case_id=event["case_id"],
            host_id=event["host_id"],
            ioc_type="file_path",
            value=executable or command[:120],
            source=event["source"],
            evidence_reference=event["evidence_reference"],
            confidence="medium" if risk == "medium" else "high",
        )


# ---------------------------------------------------------------------------
# rule 4: LINUX-PERS-002 authorized SSH key for root
# ---------------------------------------------------------------------------

def _detect_root_authorized_keys(events: list[dict], emitter: _Emitter) -> None:
    for event in events:
        if event.get("event_type") != "ssh_key_modified":
            continue
        metadata = event.get("metadata") or {}
        ssh_file = str(metadata.get("ssh_file") or "")
        if "/root/.ssh" not in ssh_file:
            continue
        key_type = str(metadata.get("key_type") or "unknown")
        comment = str(metadata.get("comment") or "")
        emitter.add_finding(
            case_id=event["case_id"],
            host_id=event["host_id"],
            title="Authorized SSH key configured for root",
            description=(
                f"An authorized {key_type} public key "
                f"{'(' + comment + ') ' if comment else ''}is configured in "
                f"{ssh_file}. SSH key access to the root account is a "
                f"persistence mechanism (MITRE T1098.004) and must be "
                f"verified against the list of approved administrator "
                f"keys. Requires analyst review."),
            severity="medium",
            rule_id="LINUX-PERS-002",
            evidence_reference=event["evidence_reference"],
            mitre_technique="T1098.004",
        )
        emitter.add_ioc(
            case_id=event["case_id"],
            host_id=event["host_id"],
            ioc_type="ssh_key",
            value=comment or key_type,
            source=event["source"],
            evidence_reference=event["evidence_reference"],
            confidence="medium",
        )


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def run_detection(events: list[dict], case_id: str | None = None
                  ) -> tuple[list[dict], list[dict]]:
    """
    Run all Linux detection rules over a list of NormalizedEvent dicts.

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

    emitter = _Emitter(platform="linux")
    _detect_brute_force(normalized_events, emitter)
    _detect_success_after_failures(normalized_events, emitter)
    _detect_suspicious_cron_jobs(normalized_events, emitter)
    _detect_root_authorized_keys(normalized_events, emitter)
    return emitter.findings, emitter.iocs
