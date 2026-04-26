import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

DEFAULT_DATA_DIR = Path.home() / "ghostplc-sensor" / "data"
DATA_DIR = Path(os.getenv("GHOSTPLC_DATA_DIR", str(DEFAULT_DATA_DIR))).expanduser()
DB_PATH = Path(os.getenv("GHOSTPLC_DB_PATH", str(DATA_DIR / "ghostplc.sqlite3"))).expanduser()

EVENT_COLUMNS = [
    "ts",
    "src_ip_hash",
    "country_code",
    "country",
    "lat",
    "lon",
    "geo_source",
    "protocol",
    "port",
    "event_type",
    "honeypot",
    "honeypot_type",
    "severity",
]


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    init_db(connection)
    return connection


def init_db(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            ts TEXT NOT NULL,
            src_ip_hash TEXT NOT NULL,
            country_code TEXT NOT NULL,
            country TEXT NOT NULL,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            geo_source TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            honeypot TEXT NOT NULL,
            honeypot_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_country ON events(country)")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_fingerprint TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            window_start TEXT NOT NULL,
            window_end TEXT NOT NULL,
            model TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            recommendations_json TEXT NOT NULL
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at)")
    connection.commit()


def insert_events(events: list[dict[str, Any]]) -> int:
    if not events:
        return 0

    with closing(connect()) as connection:
        before = connection.total_changes
        for event in events:
            connection.execute(
                f"""
                INSERT OR IGNORE INTO events (
                    event_key, {", ".join(EVENT_COLUMNS)}
                ) VALUES (
                    :event_key, {", ".join(":" + column for column in EVENT_COLUMNS)}
                )
                """,
                event,
            )
        connection.commit()
        return connection.total_changes - before


def read_recent_events(limit: int = 1000) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 10000))
    with closing(connect()) as connection:
        rows = connection.execute(
            f"""
            SELECT {", ".join(EVENT_COLUMNS)}
            FROM events
            ORDER BY ts DESC, id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    return [dict(row) for row in reversed(rows)]


def read_events_since(since_iso: str, limit: int = 500) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 5000))
    with closing(connect()) as connection:
        rows = connection.execute(
            f"""
            SELECT {", ".join(EVENT_COLUMNS)}
            FROM events
            WHERE ts >= ?
            ORDER BY ts DESC, id DESC
            LIMIT ?
            """,
            (since_iso, safe_limit),
        ).fetchall()

    return [dict(row) for row in reversed(rows)]


def read_events_between(start_iso: str, end_iso: str, limit: int = 500) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 5000))
    with closing(connect()) as connection:
        rows = connection.execute(
            f"""
            SELECT {", ".join(EVENT_COLUMNS)}
            FROM events
            WHERE ts >= ? AND ts < ?
            ORDER BY ts DESC, id DESC
            LIMIT ?
            """,
            (start_iso, end_iso, safe_limit),
        ).fetchall()

    return [dict(row) for row in reversed(rows)]


def insert_analysis(analysis: dict[str, Any]) -> bool:
    with closing(connect()) as connection:
        before = connection.total_changes
        connection.execute(
            """
            INSERT OR IGNORE INTO analyses (
                source_fingerprint,
                created_at,
                window_start,
                window_end,
                model,
                event_count,
                title,
                summary,
                findings_json,
                recommendations_json
            ) VALUES (
                :source_fingerprint,
                :created_at,
                :window_start,
                :window_end,
                :model,
                :event_count,
                :title,
                :summary,
                :findings_json,
                :recommendations_json
            )
            """,
            analysis,
        )
        connection.commit()
        return connection.total_changes > before


def read_latest_analysis() -> dict[str, Any] | None:
    with closing(connect()) as connection:
        row = connection.execute(
            """
            SELECT created_at, window_start, window_end, model, event_count, title,
                   summary, findings_json, recommendations_json
            FROM analyses
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """
        ).fetchone()

    if not row:
        return None

    payload = dict(row)
    payload["findings"] = json.loads(payload.pop("findings_json"))
    payload["recommendations"] = json.loads(payload.pop("recommendations_json"))
    return payload
