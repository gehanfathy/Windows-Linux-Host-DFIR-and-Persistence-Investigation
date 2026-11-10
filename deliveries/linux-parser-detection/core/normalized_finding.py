from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedFinding:
    finding_id: str
    rule_id: str
    severity: str
    status: str
    message: str
    evidence_reference: str
    metadata: dict[str, Any] = field(default_factory=dict)
