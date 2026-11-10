import hashlib

from core.normalized_event import NormalizedEvent


def parse_authorized_keys(
    file_path,
    case_id="CASE-001",
    host_id="LINUX-001"
):
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split()

            key_index = next(
                (
                    i for i, part in enumerate(parts)
                    if part.startswith(("ssh-", "ecdsa-", "sk-"))
                ),
                None
            )

            if key_index is None or len(parts) <= key_index + 1:
                continue

            key_type = parts[key_index]
            public_key_data = parts[key_index + 1]

            # Store only a SHA-256 identifier, never the key content.
            key_id = hashlib.sha256(
                public_key_data.encode("utf-8")
            ).hexdigest()

            comment = " ".join(parts[key_index + 2:]) or None

            events.append(
                NormalizedEvent(
                    event_id=f"LINUX-SSH-{line_number}",
                    case_id=case_id,
                    host_id=host_id,
                    platform="linux",
                    severity="info",
                    message="SSH authorized public key detected",
                    event_type="ssh_authorized_key",
                    source="authorized_keys",
                    evidence_reference=f"authorized_keys:line-{line_number}",
                    metadata={
                        "key_type": key_type,
                        "key_id": key_id,
                        "comment": comment,
                        "line_number": line_number
                    }
                )
            )

    return events
