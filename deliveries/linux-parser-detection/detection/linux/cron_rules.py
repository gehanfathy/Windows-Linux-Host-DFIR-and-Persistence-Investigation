import os
import shlex

from core.normalized_finding import NormalizedFinding


RULE_ID = "LINUX-CRON-001"

SUSPICIOUS_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/"
)

SHELL_INTERPRETERS = {
    "sh",
    "bash",
    "dash",
    "zsh"
}


def is_suspicious_path(path):
    normalized = os.path.normpath(path)

    return any(
        normalized.startswith(directory)
        for directory in SUSPICIOUS_PATHS
    )


def get_executable_targets(command):
    try:
        parts = shlex.split(command)
    except ValueError:
        return []

    if not parts:
        return []

    executable = parts[0]
    targets = [executable]

    interpreter = os.path.basename(executable)

    if interpreter in SHELL_INTERPRETERS:
        for argument in parts[1:]:
            if argument.startswith("-"):
                if argument in ("-c", "--command"):
                    return targets
                continue

            targets.append(argument)
            break

    return targets


def detect_suspicious_cron(events):
    findings = []

    for event in events:
        if event.platform != "linux":
            continue

        if event.event_type != "cron_job":
            continue

        if not event.evidence_reference:
            continue

        command = event.metadata.get("command", "")
        targets = get_executable_targets(command)

        suspicious_targets = [
            target for target in targets
            if is_suspicious_path(target)
        ]

        if not suspicious_targets:
            continue

        findings.append(
            NormalizedFinding(
                finding_id=f"{RULE_ID}-{len(findings) + 1:04d}",
                rule_id=RULE_ID,
                severity="medium",
                status="unverified",
                message=(
                    "Cron job executes a command from a temporary directory"
                ),
                evidence_reference=event.evidence_reference,
                metadata={
                    "schedule": event.metadata.get("schedule"),
                    "user": event.metadata.get("user"),
                    "command": command,
                    "suspicious_targets": suspicious_targets,
                    "line_number": event.metadata.get("line_number")
                }
            )
        )

    return findings
