import re
from core.normalized_event import NormalizedEvent

SUDO_RE = re.compile(r"\bsudo(?:\[\d+\])?:\s+(\S+)\s+:\s.*?\bCOMMAND=(.*)$")


def parse_auth_log(file_path, case_id="CASE-001", host_id="LINUX-001"):
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            event = None
            sudo_match = SUDO_RE.search(line)

            if "Failed password" in line:
                event = {
                    "event_type": "failed_login",
                    "severity": "medium",
                    "message": "Failed login attempt"
                }

            elif "Accepted password" in line or "Accepted publickey" in line:
                event = {
                    "event_type": "successful_login",
                    "severity": "low",
                    "message": "Successful login"
                }

            elif "Invalid user" in line:
                event = {
                    "event_type": "invalid_user",
                    "severity": "medium",
                    "message": "Login attempt with invalid username"
                }

            elif sudo_match:
                event = {
                    "event_type": "sudo_activity",
                    "severity": "info",
                    "message": "Sudo activity detected"
                }

            if not event:
                continue

            timestamp = re.search(
                r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
                line
            )

            username = re.search(
                r"(?:Failed password for (?:invalid user )?|Accepted (?:password|publickey) for |Invalid user )(\S+)",
                line
            )

            source_ip = re.search(
                r"from\s+([0-9a-fA-F:.]+)", line
            )

            source_port = re.search(
                r"port\s+(\d+)", line
            )

            process = re.search(
                r"\b([A-Za-z0-9_.-]+)\[\d+\]:", line
            )

            normalized_event = NormalizedEvent(
                event_id=f"LINUX-AUTH-{line_number}",
                case_id=case_id,
                host_id=host_id,
                platform="linux",
                severity=event["severity"],
                message=event["message"],

                event_type=event["event_type"],
                timestamp=timestamp.group(1) if timestamp else None,
                source="auth.log",
                evidence_reference=f"auth.log:line-{line_number}",

                metadata={
                    "raw_log": line,
                    "line_number": line_number,
                    "username": sudo_match.group(1) if sudo_match else (username.group(1) if username else None),
                    "command": sudo_match.group(2).strip() if sudo_match else None,
                    "source_ip": source_ip.group(1) if source_ip else None,
                    "source_port": int(source_port.group(1)) if source_port else None,
                    "process": process.group(1) if process else None
                }
            )

            events.append(normalized_event)

    return events
