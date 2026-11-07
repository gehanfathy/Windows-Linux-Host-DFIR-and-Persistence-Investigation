import sqlite3
from pathlib import Path


DATABASE_PATH = Path("data/dfir.db")


def get_connection() -> sqlite3.Connection:
    """
    Create and return a connection to the SQLite database.
    """

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    return connection


def init_db() -> None:
    """
    Create the initial database tables if they do not exist.
    """

    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                case_name TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                case_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                platform TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                evidence_reference TEXT NOT NULL,
                message TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT UNIQUE NOT NULL,
                case_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                platform TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unverified',
                evidence_reference TEXT NOT NULL,
                mitre_technique TEXT,
                related_evidence_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id TEXT UNIQUE NOT NULL,
                case_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                evidence_reference TEXT NOT NULL,
                confidence TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

        # Migration for databases created before the related_evidence field
        try:
            connection.execute(
                "ALTER TABLE findings ADD COLUMN related_evidence_json TEXT"
            )
        except sqlite3.OperationalError:
            pass  # column already exists
