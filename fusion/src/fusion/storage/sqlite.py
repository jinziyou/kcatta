"""SQLite-backed record store with indexed append and tail queries."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from pydantic import BaseModel

# Fixed table names — never derived from user input.
TABLE_ASSET_REPORTS = "asset_reports"
TABLE_FLOW_BATCHES = "flow_batches"
TABLE_VULNERABILITIES = "vulnerabilities"
TABLE_ALERTS = "alerts"
TABLE_CAPABILITY_GRAPHS = "capability_graphs"

_ALL_TABLES = (
    TABLE_ASSET_REPORTS,
    TABLE_FLOW_BATCHES,
    TABLE_VULNERABILITIES,
    TABLE_ALERTS,
    TABLE_CAPABILITY_GRAPHS,
)


class SqliteStore:
    """Append Pydantic models to a SQLite table; ``tail`` reads newest rows only."""

    def __init__(self, db_path: str | Path, table: str) -> None:
        if table not in _ALL_TABLES:
            msg = f"unknown table {table!r}"
            raise ValueError(msg)
        self._db_path = Path(db_path)
        self._table = table
        self._ensure_schema()

    @property
    def db_path(self) -> Path:
        """Filesystem path of the backing SQLite database."""
        return self._db_path

    @property
    def table(self) -> str:
        """Name of the table this store reads from and writes to."""
        return self._table

    def _connect(self) -> sqlite3.Connection:
        # sqlite3's connection context manager only commits/rolls back; it does
        # NOT close. Every caller wraps this in contextlib.closing() so the
        # connection (and its file handle / WAL reference) is released promptly
        # rather than left to the garbage collector.
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        # Wait (rather than fail immediately) if another writer holds the lock.
        # Matches sqlite3.connect's default 5s timeout; explicit for clarity.
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _ensure_schema(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._table} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def append(self, record: BaseModel) -> None:
        """Insert a model as a JSON payload row into the table."""
        with closing(self._connect()) as conn:
            conn.execute(
                f"INSERT INTO {self._table} (payload) VALUES (?)",
                (record.model_dump_json(),),
            )
            conn.commit()

    def tail(self, limit: int) -> list[dict]:
        """Return up to ``limit`` most recently inserted records, newest first."""
        if limit <= 0:
            return []
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT payload FROM {self._table} ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def find_one(self, field: str, value: str) -> dict | None:
        """Return the newest record whose top-level JSON field equals ``value``."""
        with closing(self._connect()) as conn:
            row = conn.execute(
                f"""
                SELECT payload FROM {self._table}
                WHERE json_extract(payload, ?) = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (f"$.{field}", value),
            ).fetchone()
        return json.loads(row["payload"]) if row else None
