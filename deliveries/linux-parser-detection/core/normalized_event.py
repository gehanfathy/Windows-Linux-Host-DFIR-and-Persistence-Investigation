from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedEvent:
    event_id: str
    case_id: str
    host_id: str
    platform: str
    severity: str
    message: str

    event_type: str | None = None
    timestamp: str | None = None
    source: str | None = None
    evidence_reference: str | None = None

    metadata: dict[str, Any] = field(default_factory=dict)
