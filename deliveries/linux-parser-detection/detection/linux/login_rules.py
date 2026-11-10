
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from core.normalized_finding import NormalizedFinding


RULE_ID = "LINUX-AUTH-001"


def _parse_timestamp(value, year=None):
    """Parse ISO timestamps and traditional Linux syslog timestamps."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(
                f"{year or datetime.now().year} {value}",
                "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed


def detect_repeated_failed_logins(
    events,
    threshold=5,
    window_minutes=5,
    year=None
):
    if threshold < 1 or window_minutes < 1:
        raise ValueError("Threshold and window must be positive")

    grouped_events = defaultdict(list)

    for event in events:
        if event.platform != "linux":
            continue

        if event.event_type != "failed_login":
            continue

        source_ip = event.metadata.get("source_ip")
        timestamp = _parse_timestamp(event.timestamp, year)

        if not source_ip or not timestamp:
            continue

        grouped_events[source_ip].append((timestamp, event))

    findings = []
    window = timedelta(minutes=window_minutes)

    for source_ip, attempts in grouped_events.items():
        attempts.sort(key=lambda item: item[0])

        left = 0

        for right in range(len(attempts)):
            while attempts[right][0] - attempts[left][0] > window:
                left += 1

            current_attempts = attempts[left:right + 1]

            if len(current_attempts) < threshold:
                continue

            evidence = [
                item[1].evidence_reference
                for item in current_attempts
                if item[1].evidence_reference
            ]

            if not evidence:
                continue

            findings.append(
                NormalizedFinding(
                    finding_id=f"{RULE_ID}-{len(findings) + 1:04d}",
                    rule_id=RULE_ID,
                    severity="medium",
                    status="unverified",
                    message=(
                        f"Detected {len(current_attempts)} failed login "
                        f"attempts from {source_ip} within "
                        f"{window_minutes} minutes"
                    ),
                    evidence_reference=", ".join(evidence),
                    metadata={
                        "source_ip": source_ip,
                        "failed_attempts": len(current_attempts),
                        "threshold": threshold,
                        "window_minutes": window_minutes,
                    }
                )
            )

            # Avoid generating duplicate findings for overlapping windows.
            left = right + 1

    return findings
