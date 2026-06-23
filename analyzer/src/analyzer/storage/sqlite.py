"""SQLite-backed record store with indexed append and tail queries.

F1 scalability: each table indexes its common ``find_one`` query key (e.g.
``report_id`` / ``alert_id`` / ``job_id``) via a JSON expression index, so a
point lookup is an index seek rather than a full-table ``json_extract`` scan.
A single connection is kept open and reused for appends (one connection +
commit per row was the previous hot path), instead of opening/closing per write.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import closing
from pathlib import Path

from pydantic import BaseModel

# Fixed table names — never derived from user input.
TABLE_ASSET_REPORTS = "asset_reports"
TABLE_TRACE_BATCHES = "trace_batches"
TABLE_GUARD_EVENTS = "guard_events"
TABLE_VULNERABILITIES = "vulnerabilities"
TABLE_ALERTS = "alerts"
TABLE_ALERT_STATES = "alert_states"
TABLE_CAPABILITY_GRAPHS = "capability_graphs"
TABLE_SCAN_TARGETS = "scan_targets"
TABLE_SCAN_JOBS = "scan_jobs"

_ALL_TABLES = (
    TABLE_ASSET_REPORTS,
    TABLE_TRACE_BATCHES,
    TABLE_GUARD_EVENTS,
    TABLE_VULNERABILITIES,
    TABLE_ALERTS,
    TABLE_ALERT_STATES,
    TABLE_CAPABILITY_GRAPHS,
    TABLE_SCAN_TARGETS,
    TABLE_SCAN_JOBS,
)

# The JSON top-level keys each table is point-queried by (find_one) / filtered by.
# An expression index is created for each so the lookup is a seek, not a scan.
_INDEXED_FIELDS: dict[str, tuple[str, ...]] = {
    TABLE_ASSET_REPORTS: ("report_id",),
    TABLE_TRACE_BATCHES: ("batch_id",),
    TABLE_GUARD_EVENTS: ("batch_id", "host_id"),
    TABLE_VULNERABILITIES: ("report_id", "host_id"),
    TABLE_ALERTS: ("alert_id",),
    # Triage overlay is point-queried by alert_key (newest state per alert).
    TABLE_ALERT_STATES: ("alert_key",),
    TABLE_CAPABILITY_GRAPHS: (),
    TABLE_SCAN_TARGETS: ("target_id",),
    TABLE_SCAN_JOBS: ("job_id",),
}

# Only plain JSON identifiers are ever used as field names (we control all call
# sites); validate defensively so a field name can never inject into SQL.
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SqliteStore:
    """Append Pydantic models to a SQLite table; ``tail`` reads newest rows only."""

    def __init__(self, db_path: str | Path, table: str) -> None:
        if table not in _ALL_TABLES:
            msg = f"unknown table {table!r}"
            raise ValueError(msg)
        self._db_path = Path(db_path)
        self._table = table
        self._write_conn: sqlite3.Connection | None = None
        # The long-lived write connection is shared across threads (appends can
        # run on a worker thread, e.g. a scan job's asyncio.to_thread); a SQLite
        # connection is not safe for concurrent use, so serialize writes.
        self._write_lock = threading.Lock()
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
        # NOT close. Read callers wrap this in contextlib.closing() so the
        # connection is released promptly; the write connection is long-lived.
        # check_same_thread=False: the long-lived write connection may be used
        # from a worker thread (scan jobs run via asyncio.to_thread); concurrent
        # use is serialized by `_write_lock` (per-call read connections created
        # here are used only in their creating thread).
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        # synchronous=NORMAL is the recommended companion to WAL: durable across
        # application crashes (only a power loss can lose the last txn), while
        # avoiding an fsync per commit — that fsync was the per-row append cost.
        conn.execute("PRAGMA synchronous=NORMAL")
        # Wait (rather than fail immediately) if another writer holds the lock.
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _write_connection(self) -> sqlite3.Connection:
        """The store's single long-lived write connection (lazily opened).

        Reused across appends so a burst of inserts no longer pays a
        connect + WAL-setup + close per row.
        """
        if self._write_conn is None:
            self._write_conn = self._connect()
        return self._write_conn

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
            for field in _INDEXED_FIELDS.get(self._table, ()):
                # Expression index matching the find_one predicate verbatim so the
                # planner uses it. Field names are constants from this module.
                conn.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_{self._table}_{field} "
                    f"ON {self._table} (json_extract(payload, '$.{field}'))"
                )
            conn.commit()

    def append(self, record: BaseModel) -> None:
        """Insert a model as a JSON payload row, reusing the write connection."""
        payload = record.model_dump_json()
        with self._write_lock:
            conn = self._write_connection()
            conn.execute(
                f"INSERT INTO {self._table} (payload) VALUES (?)",
                (payload,),
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
        """Return the newest record whose top-level JSON field equals ``value``.

        When ``field`` is one of the table's indexed keys the predicate matches
        the expression index verbatim, so this is an index seek rather than a
        full-table scan. Unknown fields still resolve correctly (falling back to
        a scan) for parity with ``JsonlStore.find_one``.
        """
        if not _FIELD_RE.match(field):
            return None
        with closing(self._connect()) as conn:
            row = conn.execute(
                f"""
                SELECT payload FROM {self._table}
                WHERE json_extract(payload, '$.{field}') = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (value,),
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def fingerprint(self) -> tuple[int, int]:
        """Cheap (row_count, max_rowid) snapshot of the table's current state.

        Used to invalidate derived caches (e.g. attack-path prediction) without
        rereading/parsing every record. Append-only tables change this tuple on
        every write, so an unchanged fingerprint means an unchanged dataset.
        """
        with closing(self._connect()) as conn:
            row = conn.execute(
                f"SELECT COUNT(*), COALESCE(MAX(id), 0) FROM {self._table}"
            ).fetchone()
        return (int(row[0]), int(row[1])) if row else (0, 0)

    def close(self) -> None:
        """Close the long-lived write connection, if open."""
        if self._write_conn is not None:
            self._write_conn.close()
            self._write_conn = None
