import json
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI

from app.database.db import get_connection, init_db
from app.models.schemas import NormalizedEvent


app = FastAPI(
    title="DFIR Investigation API",
    description="Backend API for Windows and Linux DFIR investigations",
    version="0.2.0",
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
        "version": "0.2.0",
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
