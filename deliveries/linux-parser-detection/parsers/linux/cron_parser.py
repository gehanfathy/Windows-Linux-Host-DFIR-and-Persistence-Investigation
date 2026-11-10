import re
from core.normalized_event import NormalizedEvent


def parse_cron_file(
    file_path,
    case_id="CASE-001",
    host_id="LINUX-001",
    system_crontab=False,
    default_user=None
):
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()

            if not line or line.startswith("#") or "=" in line.split()[0]:
                continue

            parts = line.split()

            if parts[0].startswith("@"):
                schedule_fields = 1
            else:
                schedule_fields = 5

            if len(parts) <= schedule_fields:
                continue

            schedule = " ".join(parts[:schedule_fields])

            if system_crontab:
                if len(parts) <= schedule_fields + 1:
                    continue

                user = parts[schedule_fields]
                command = " ".join(parts[schedule_fields + 1:])
            else:
                user = default_user
                command = " ".join(parts[schedule_fields:])

            path_match = re.search(
                r"(?<![\w.-])(/[A-Za-z0-9_./-]+)",
                command
            )

            command_path = path_match.group(1) if path_match else None

            events.append(
                NormalizedEvent(
                    event_id=f"LINUX-CRON-{line_number}",
                    case_id=case_id,
                    host_id=host_id,
                    platform="linux",
                    severity="info",
                    message="Cron scheduled task detected",
                    event_type="cron_job",
                    source="crontab",
                    evidence_reference=f"crontab:line-{line_number}",
                    metadata={
                        "line_number": line_number,
                        "schedule": schedule,
                        "user": user,
                        "command": command,
                        "path": command_path,
                        "raw_log": line
                    }
                )
            )

    return events
