import json
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI

from app.database.db import get_connection, init_db
from app.models.schemas import NormalizedEvent, NormalizedFinding, NormalizedIOC


app = FastAPI(
    title="DFIR Investigation API",
    description="Backend API for Windows and Linux DFIR investigations",
    version="0.3.0",
)


@app.on_event("startup")
def startup_event() -> None:
    """
    Initialize the SQLite database when the API starts.
    """

    init_db()


@app.get("/health")
def health_check() -> dict[str, str]:
    """
    Check whether the API is running.
    """

    return {
        "status": "ok",
        "service": "dfir-api",
        "version": "0.3.0",
    }


@app.post("/events")
def create_event(event: NormalizedEvent) -> dict[str, Any]:
    """
    Validate and save one normalized event in SQLite.
    """

    event_data = event.model_dump()

    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO events (
                event_id,
                case_id,
                host_id,
                platform,
                event_type,
                timestamp,
                severity,
                source,
                evidence_reference,
                message,
                metadata_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_data["event_id"],
                event_data["case_id"],
                event_data["host_id"],
                event_data["platform"],
                event_data["event_type"],
                event_data["timestamp"].isoformat(),
                event_data["severity"],
                event_data["source"],
                event_data["evidence_reference"],
                event_data["message"],
                json.dumps(event_data["metadata"]),
                created_at,
            ),
        )

        connection.commit()

    return {
        "status": "created",
        "event_id": event.event_id,
    }


@app.get("/events")
def list_events() -> list[dict[str, Any]]:
    """
    Return all saved events from SQLite.
    """

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                event_id,
                case_id,
                host_id,
                platform,
                event_type,
                timestamp,
                severity,
                source,
                evidence_reference,
                message,
                metadata_json,
                created_at
            FROM events
            ORDER BY timestamp DESC
            """
        ).fetchall()

    events = []

    for row in rows:
        event = dict(row)
        event["metadata"] = json.loads(event.pop("metadata_json"))
        events.append(event)

    return events


@app.post("/findings")
def create_finding(finding: NormalizedFinding) -> dict[str, Any]:
    """
    Validate and save one detection finding in SQLite.
    """

    finding_data = finding.model_dump()

    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO findings (
                finding_id,
                case_id,
                host_id,
                platform,
                title,
                description,
                severity,
                rule_id,
                status,
                evidence_reference,
                mitre_technique,
                related_evidence_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_data["finding_id"],
                finding_data["case_id"],
                finding_data["host_id"],
                finding_data["platform"],
                finding_data["title"],
                finding_data["description"],
                finding_data["severity"],
                finding_data["rule_id"],
                finding_data["status"],
                finding_data["evidence_reference"],
                finding_data["mitre_technique"],
                json.dumps(finding_data.get("related_evidence", [])),
                created_at,
            ),
        )

        connection.commit()

    return {
        "status": "created",
        "finding_id": finding.finding_id,
    }


@app.get("/findings")
def list_findings() -> list[dict[str, Any]]:
    """
    Return all saved detection findings from SQLite.
    """

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                finding_id,
                case_id,
                host_id,
                platform,
                title,
                description,
                severity,
                rule_id,
                status,
                evidence_reference,
                mitre_technique,
                related_evidence_json,
                created_at
            FROM findings
            ORDER BY created_at DESC
            """
        ).fetchall()

    findings = []

    for row in rows:
        finding = dict(row)
        finding["related_evidence"] = json.loads(
            finding.pop("related_evidence_json") or "[]"
        )
        findings.append(finding)

    return findings


@app.post("/iocs")
def create_ioc(ioc: NormalizedIOC) -> dict[str, Any]:
    """
    Validate and save one IOC in SQLite.
    """

    ioc_data = ioc.model_dump()

    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO iocs (
                ioc_id,
                case_id,
                host_id,
                ioc_type,
                value,
                source,
                evidence_reference,
                confidence,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ioc_data["ioc_id"],
                ioc_data["case_id"],
                ioc_data["host_id"],
                ioc_data["ioc_type"],
                ioc_data["value"],
                ioc_data["source"],
                ioc_data["evidence_reference"],
                ioc_data["confidence"],
                created_at,
            ),
        )

        connection.commit()

    return {
        "status": "created",
        "ioc_id": ioc.ioc_id,
    }


@app.get("/iocs")
def list_iocs() -> list[dict[str, Any]]:
    """
    Return all saved IOCs from SQLite.
    """

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                ioc_id,
                case_id,
                host_id,
                ioc_type,
                value,
                source,
                evidence_reference,
                confidence,
                created_at
            FROM iocs
            ORDER BY created_at DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]
