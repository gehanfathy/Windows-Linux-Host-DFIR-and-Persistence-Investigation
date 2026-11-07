from datetime import datetime
from typing import Any, Dict, Literal

from pydantic import BaseModel, Field


Platform = Literal["windows", "linux"]

Severity = Literal["low", "medium", "high", "critical"]

FindingStatus = Literal[
    "unverified",
    "confirmed",
    "rejected",
    "inconclusive",
]

Confidence = Literal["low", "medium", "high"]


class NormalizedEvent(BaseModel):
    """
    Common event format for Windows and Linux evidence.
    """

    event_id: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    host_id: str = Field(..., min_length=1)
    platform: Platform
    event_type: str = Field(..., min_length=1)
    timestamp: datetime
    severity: Severity
    source: str = Field(..., min_length=1)
    evidence_reference: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NormalizedFinding(BaseModel):
    """
    Common detection finding format for Windows and Linux.
    """

    finding_id: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    host_id: str = Field(..., min_length=1)
    platform: Platform
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    severity: Severity
    rule_id: str = Field(..., min_length=1)
    status: FindingStatus = "unverified"
    evidence_reference: str = Field(..., min_length=1)
    mitre_technique: str | None = None
    related_evidence: list[str] = Field(default_factory=list)


class NormalizedIOC(BaseModel):
    """
    Common Indicator of Compromise format.
    """

    ioc_id: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    host_id: str = Field(..., min_length=1)
    ioc_type: str = Field(..., min_length=1)
    value: str = Field(..., min_length=1)
    source: str = Field(..., min_length=1)
    evidence_reference: str = Field(..., min_length=1)
    confidence: Confidence
