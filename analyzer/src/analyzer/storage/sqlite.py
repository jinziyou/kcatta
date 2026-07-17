"""SQLite-backed record store with indexed append and tail queries.

F1 scalability: each table indexes its common ``find_one`` query key (e.g.
``report_id`` / ``alert_id`` / ``batch_id``) via a JSON expression index, so a
point lookup is an index seek rather than a full-table ``json_extract`` scan.
Chunked report/trace roots use a second deterministic expression index so
lineage reads seek directly to one logical upload.
A single connection is kept open and reused for appends (one connection +
commit per row was the previous hot path), instead of opening/closing per write.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from typing import cast

from pydantic import BaseModel

from .errors import StorageCapacityError, StorageCursorError
from .lineage import LineageKind, lineage_root

# Production-safe defaults. ``ANALYZER_SQLITE_MAX_BYTES`` is a budget for the
# database plus its WAL reserve, not just one table. Set either value to 0 only
# for an externally quota-managed datastore.
DEFAULT_MAX_BYTES = 1024 * 1024 * 1024
DEFAULT_WAL_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_BYTES_PER_TABLE = 96 * 1024 * 1024
DEFAULT_MAX_ROWS_PER_TABLE = 100_000
DEFAULT_MAX_RECORD_BYTES = 12 * 1024 * 1024
DEFAULT_READ_MAX_BYTES = 32 * 1024 * 1024
_SHM_RESERVE_BYTES = 32 * 1024
_WRITE_OVERHEAD_BYTES = 64 * 1024

# Fixed table names — never derived from user input.
TABLE_ASSET_REPORTS = "asset_reports"
TABLE_TRACE_BATCHES = "trace_batches"
TABLE_GUARD_EVENTS = "guard_events"
TABLE_MDE_SECURITY_BATCHES = "mde_security_batches"
TABLE_MDVM_VULNERABILITY_BATCHES = "mdvm_vulnerability_batches"
TABLE_VULNERABILITIES = "vulnerabilities"
TABLE_ALERTS = "alerts"
TABLE_ALERT_STATES = "alert_states"
TABLE_CAPABILITY_GRAPHS = "capability_graphs"
# Shared persistence primitives for Form. They remain valid table names here,
# but Analyzer's FastAPI app never initializes or reads them.
TABLE_SCAN_TARGETS = "scan_targets"
TABLE_SCAN_JOBS = "scan_jobs"

_ALL_TABLES = (
    TABLE_ASSET_REPORTS,
    TABLE_TRACE_BATCHES,
    TABLE_GUARD_EVENTS,
    TABLE_MDE_SECURITY_BATCHES,
    TABLE_MDVM_VULNERABILITY_BATCHES,
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
    TABLE_MDE_SECURITY_BATCHES: ("batch_id",),
    TABLE_MDVM_VULNERABILITY_BATCHES: ("batch_id",),
    TABLE_VULNERABILITIES: ("report_id", "host_id"),
    TABLE_ALERTS: ("alert_id",),
    # Triage overlay is point-queried by alert_key (newest state per alert).
    TABLE_ALERT_STATES: ("alert_key",),
    TABLE_CAPABILITY_GRAPHS: (),
    TABLE_SCAN_TARGETS: ("target_id",),
    TABLE_SCAN_JOBS: ("job_id",),
}

# Tables whose logical uploads may span multiple physical records. The
# expression index maps both root and recognized chunk ids to one root key.
_LINEAGE_FIELDS: dict[str, tuple[str, LineageKind]] = {
    TABLE_ASSET_REPORTS: ("report_id", "asset"),
    TABLE_VULNERABILITIES: ("report_id", "asset"),
    TABLE_TRACE_BATCHES: ("batch_id", "trace"),
}
_LINEAGE_SQL_FUNCTION = "kcatta_lineage_key_v1"

# Only plain JSON identifiers are ever used as field names (we control all call
# sites); validate defensively so a field name can never inject into SQL.
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_STATS_TABLE = "_storage_stats"
_DB_LOCKS_GUARD = threading.Lock()
_DB_WRITE_LOCKS: dict[Path, threading.RLock] = {}


def _nonnegative_limit(explicit: int | None, env_name: str, default: int) -> int:
    raw: int | str = explicit if explicit is not None else os.getenv(env_name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{env_name} must be a non-negative integer") from exc
    if value < 0:
        raise ValueError(f"{env_name} must be a non-negative integer")
    return value


def _sqlite_capacity_error(exc: sqlite3.Error) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    return code == sqlite3.SQLITE_FULL or "database or disk is full" in str(exc).lower()


def _shared_write_lock(db_path: Path) -> threading.RLock:
    """One process-wide writer/quota transaction lock per physical database."""
    key = db_path.absolute()
    with _DB_LOCKS_GUARD:
        return _DB_WRITE_LOCKS.setdefault(key, threading.RLock())


def _sqlite_lineage_key(value: object, kind: str) -> str | None:
    """Total SQLite callback: invalid historical values produce a NULL key."""
    if not isinstance(value, str) or kind not in {"asset", "trace"}:
        return None
    return lineage_root(value, cast(LineageKind, kind))


class SqliteStore:
    """Append Pydantic models to a SQLite table; ``tail`` reads newest rows only."""

    def __init__(
        self,
        db_path: str | Path,
        table: str,
        *,
        max_bytes: int | None = None,
        wal_max_bytes: int | None = None,
        max_table_bytes: int | None = None,
        max_rows: int | None = None,
        max_record_bytes: int | None = None,
        read_max_bytes: int | None = None,
    ) -> None:
        if table not in _ALL_TABLES:
            msg = f"unknown table {table!r}"
            raise ValueError(msg)
        self._db_path = Path(db_path)
        self._table = table
        self._max_bytes = _nonnegative_limit(
            max_bytes,
            "ANALYZER_SQLITE_MAX_BYTES",
            DEFAULT_MAX_BYTES,
        )
        self._wal_max_bytes = _nonnegative_limit(
            wal_max_bytes,
            "ANALYZER_SQLITE_WAL_MAX_BYTES",
            DEFAULT_WAL_MAX_BYTES,
        )
        self._max_table_bytes = _nonnegative_limit(
            max_table_bytes,
            "ANALYZER_SQLITE_MAX_TABLE_BYTES",
            DEFAULT_MAX_BYTES_PER_TABLE,
        )
        self._max_rows = _nonnegative_limit(
            max_rows,
            "ANALYZER_SQLITE_MAX_ROWS_PER_TABLE",
            DEFAULT_MAX_ROWS_PER_TABLE,
        )
        self._max_record_bytes = _nonnegative_limit(
            max_record_bytes,
            "ANALYZER_STORAGE_MAX_RECORD_BYTES",
            DEFAULT_MAX_RECORD_BYTES,
        )
        self._read_max_bytes = _nonnegative_limit(
            read_max_bytes,
            "ANALYZER_STORAGE_READ_MAX_BYTES",
            DEFAULT_READ_MAX_BYTES,
        )
        if self._max_bytes and self._wal_max_bytes >= self._max_bytes:
            raise ValueError(
                "ANALYZER_SQLITE_WAL_MAX_BYTES must be smaller than ANALYZER_SQLITE_MAX_BYTES"
            )
        self._write_conn: sqlite3.Connection | None = None
        # The long-lived write connection can be shared across request/worker
        # threads; a SQLite connection is not safe for concurrent use, so
        # serialize writes.
        self._write_lock = _shared_write_lock(self._db_path)
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
        # from different request/worker threads; concurrent use is serialized by
        # `_write_lock` (per-call reads stay in their creating thread).
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.create_function(
            _LINEAGE_SQL_FUNCTION,
            2,
            _sqlite_lineage_key,
            deterministic=True,
        )
        conn.execute("PRAGMA journal_mode=WAL")
        # synchronous=NORMAL is the recommended companion to WAL: durable across
        # application crashes (only a power loss can lose the last txn), while
        # avoiding an fsync per commit — that fsync was the per-row append cost.
        conn.execute("PRAGMA synchronous=NORMAL")
        # Wait (rather than fail immediately) if another writer holds the lock.
        conn.execute("PRAGMA busy_timeout=5000")
        if self._wal_max_bytes:
            conn.execute(f"PRAGMA journal_size_limit={self._wal_max_bytes}")
            page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
            # Checkpoint well before the WAL reserve is exhausted. This also
            # keeps the transient WAL bounded in the normal short-reader API.
            checkpoint_pages = max(1, min(1000, self._wal_max_bytes // page_size // 2))
            conn.execute(f"PRAGMA wal_autocheckpoint={checkpoint_pages}")
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
            try:
                self._apply_page_budget(conn)
                conn.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._table} (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        payload TEXT NOT NULL,
                        payload_bytes INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )
                columns = {
                    str(row["name"])
                    for row in conn.execute(f"PRAGMA table_info({self._table})").fetchall()
                }
                if "payload_bytes" not in columns:
                    conn.execute(
                        f"ALTER TABLE {self._table} "
                        "ADD COLUMN payload_bytes INTEGER NOT NULL DEFAULT 0"
                    )
                # One-time, idempotent backfill for databases created before the
                # logical byte-budget column existed.
                conn.execute(
                    f"UPDATE {self._table} "
                    "SET payload_bytes = length(CAST(payload AS BLOB)) "
                    "WHERE payload_bytes = 0"
                )
                conn.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {_STATS_TABLE} (
                        table_name TEXT PRIMARY KEY,
                        row_count INTEGER NOT NULL,
                        total_bytes INTEGER NOT NULL
                    )
                    """
                )
                conn.execute(
                    f"""
                    INSERT INTO {_STATS_TABLE} (table_name, row_count, total_bytes)
                    SELECT ?, COUNT(*), COALESCE(SUM(payload_bytes), 0)
                    FROM {self._table}
                    WHERE true
                    ON CONFLICT(table_name) DO UPDATE SET
                        row_count = excluded.row_count,
                        total_bytes = excluded.total_bytes
                    """,
                    (self._table,),
                )
                conn.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS trg_{self._table}_storage_insert
                    AFTER INSERT ON {self._table}
                    BEGIN
                        UPDATE {_STATS_TABLE}
                        SET row_count = row_count + 1,
                            total_bytes = total_bytes + NEW.payload_bytes
                        WHERE table_name = '{self._table}';
                    END
                    """
                )
                conn.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS trg_{self._table}_storage_delete
                    AFTER DELETE ON {self._table}
                    BEGIN
                        UPDATE {_STATS_TABLE}
                        SET row_count = row_count - 1,
                            total_bytes = total_bytes - OLD.payload_bytes
                        WHERE table_name = '{self._table}';
                    END
                    """
                )
                for field in _INDEXED_FIELDS.get(self._table, ()):
                    # Expression index matching the find_one predicate verbatim so the
                    # planner uses it. Field names are constants from this module.
                    conn.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_{self._table}_{field} "
                        f"ON {self._table} (json_extract(payload, '$.{field}'))"
                    )
                if lineage := _LINEAGE_FIELDS.get(self._table):
                    field, kind = lineage
                    conn.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_{self._table}_{field}_lineage_v1 "
                        f"ON {self._table} "
                        f"({_LINEAGE_SQL_FUNCTION}(json_extract(payload, '$.{field}'), '{kind}'))"
                    )
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                if _sqlite_capacity_error(exc):
                    raise StorageCapacityError(
                        "SQLite quota prevented schema migration; increase "
                        "ANALYZER_SQLITE_MAX_BYTES or prune and VACUUM the database offline"
                    ) from exc
                raise

    def _apply_page_budget(self, conn: sqlite3.Connection) -> None:
        """Persist a database-page ceiling while reserving space for WAL/SHM.

        SQLite's ``max_page_count`` is enforced before a transaction commits.
        The separate WAL reserve is kept small with ``journal_size_limit`` and
        auto-checkpointing, so the configured total is a meaningful volume
        budget rather than an unbounded append target.
        """
        if self._max_bytes <= 0:
            return
        page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        database_budget = self._max_bytes - self._wal_max_bytes - _SHM_RESERVE_BYTES
        page_limit = database_budget // page_size
        if page_limit < 4:
            raise ValueError(
                "ANALYZER_SQLITE_MAX_BYTES leaves too little space for a SQLite database"
            )
        page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        if page_count > page_limit:
            raise StorageCapacityError(
                f"existing SQLite database uses {page_count * page_size} bytes, above the "
                f"configured database-page budget {page_limit * page_size}; increase "
                "ANALYZER_SQLITE_MAX_BYTES or prune and VACUUM it offline"
            )
        # Integers originate from validated configuration, never request data.
        applied = int(conn.execute(f"PRAGMA max_page_count={page_limit}").fetchone()[0])
        if applied != page_limit:
            raise StorageCapacityError(
                f"SQLite refused the configured page ceiling ({applied} != {page_limit})"
            )

    def append(self, record: BaseModel) -> None:
        """Insert a model under the row and database byte budgets.

        Oldest rows are removed in the same transaction *before* the insert so
        their pages can be reused at the hard page ceiling. If the new record
        still cannot fit, SQLite rolls the deletion back and the API returns a
        retryable storage-capacity response instead of acknowledging data loss.
        """
        payload = record.model_dump_json()
        payload_bytes = len(payload.encode("utf-8"))
        if self._max_record_bytes and payload_bytes > self._max_record_bytes:
            raise StorageCapacityError(f"record exceeds the maximum record size for {self._table}")
        if self._max_table_bytes and payload_bytes > self._max_table_bytes:
            raise StorageCapacityError(f"record exceeds the logical byte budget for {self._table}")
        with self._write_lock:
            conn = self._write_connection()
            try:
                self._ensure_write_budget(conn, payload_bytes)
                self._prune_for_insert(conn, payload_bytes)
                conn.execute(
                    f"INSERT INTO {self._table} (payload, payload_bytes) VALUES (?, ?)",
                    (payload, payload_bytes),
                )
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                if _sqlite_capacity_error(exc):
                    raise StorageCapacityError(
                        f"SQLite storage budget is exhausted for {self._table}"
                    ) from exc
                raise

    def _prune_for_insert(self, conn: sqlite3.Connection, incoming_bytes: int) -> None:
        """Delete the minimum oldest prefix needed by row and byte retention."""
        if self._max_rows <= 0 and self._max_table_bytes <= 0:
            return
        row = conn.execute(
            f"SELECT row_count, total_bytes FROM {_STATS_TABLE} WHERE table_name = ?",
            (self._table,),
        ).fetchone()
        count = int(row[0])
        total_bytes = int(row[1])
        excess_rows = max(0, count + 1 - self._max_rows) if self._max_rows else 0
        excess_bytes = (
            max(0, total_bytes + incoming_bytes - self._max_table_bytes)
            if self._max_table_bytes
            else 0
        )
        if excess_rows == 0 and excess_bytes == 0:
            return
        removed_bytes = 0
        cutoff: int | None = None
        for removed_rows, old in enumerate(
            conn.execute(f"SELECT id, payload_bytes FROM {self._table} ORDER BY id ASC"),
            start=1,
        ):
            cutoff = int(old["id"])
            removed_bytes += int(old["payload_bytes"])
            if removed_rows >= excess_rows and removed_bytes >= excess_bytes:
                break
        if cutoff is not None:
            conn.execute(f"DELETE FROM {self._table} WHERE id <= ?", (cutoff,))

    def _ensure_write_budget(self, conn: sqlite3.Connection, payload_bytes: int) -> None:
        """Reject writes before DB + WAL + SHM can cross the total budget."""
        if self._max_bytes <= 0:
            return
        # Payload text plus JSON-expression index updates and SQLite page
        # metadata. Two payload lengths is deliberately conservative; the hard
        # page ceiling remains the final guard.
        estimated_growth = payload_bytes * 2 + _WRITE_OVERHEAD_BYTES
        current = sum(
            candidate.stat().st_size
            for candidate in (
                self._db_path,
                Path(f"{self._db_path}-wal"),
                Path(f"{self._db_path}-shm"),
            )
            if candidate.exists()
        )
        if current + estimated_growth > self._max_bytes:
            # A normal auto-checkpoint may simply not have run yet. Try one
            # bounded passive checkpoint before applying backpressure; a long
            # reader that pins the WAL leaves ``current`` high and is rejected.
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            current = sum(
                candidate.stat().st_size
                for candidate in (
                    self._db_path,
                    Path(f"{self._db_path}-wal"),
                    Path(f"{self._db_path}-shm"),
                )
                if candidate.exists()
            )
        if current + estimated_growth > self._max_bytes:
            raise StorageCapacityError(
                f"SQLite storage budget is exhausted for {self._table} "
                f"({current} bytes used, {self._max_bytes} configured)"
            )

    def tail(self, limit: int, offset: int = 0) -> list[dict]:
        """Return a stable newest-first page of retained records.

        ``offset`` is an insertion-order offset; its default preserves the
        original ``tail(limit)`` contract.
        """
        if limit <= 0 or offset < 0:
            return []
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT payload, payload_bytes FROM {self._table} "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            records: list[dict] = []
            consumed = 0
            for row in rows:
                size = int(row["payload_bytes"])
                if self._read_max_bytes and consumed + size > self._read_max_bytes:
                    break
                records.append(json.loads(row["payload"]))
                consumed += size
        return records

    def cursor_page(
        self,
        limit: int,
        anchor: str | None = None,
        *,
        field: str | None = None,
        value: str | None = None,
    ) -> tuple[list[dict], str | None, bool]:
        """Seek newest-first by immutable row id, unaffected by later inserts."""

        if limit <= 0:
            return [], None, False
        if (field is None) != (value is None) or (field is not None and not _FIELD_RE.match(field)):
            raise StorageCursorError("invalid cursor filter")
        before: int | None = None
        if anchor is not None:
            try:
                before = int(anchor)
            except ValueError as exc:
                raise StorageCursorError("invalid SQLite cursor anchor") from exc
            if before <= 0:
                raise StorageCursorError("invalid SQLite cursor anchor")
        predicates: list[str] = []
        params: list[object] = []
        if before is not None:
            predicates.append("id < ?")
            params.append(before)
        if field is not None:
            predicates.append(f"json_extract(payload, '$.{field}') = ?")
            params.append(value)
        where = f"WHERE {' AND '.join(predicates)}" if predicates else ""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT id, payload, payload_bytes FROM {self._table} "
                f"{where} ORDER BY id DESC LIMIT ?",
                (*params, limit),
            )
            records: list[dict] = []
            consumed = 0
            last_id: int | None = None
            for row in rows:
                size = int(row["payload_bytes"])
                if self._read_max_bytes and consumed + size > self._read_max_bytes:
                    break
                records.append(json.loads(row["payload"]))
                consumed += size
                last_id = int(row["id"])
            if last_id is None:
                return [], None, False
            more_predicates = ["id < ?"]
            more_params: list[object] = [last_id]
            if field is not None:
                more_predicates.append(f"json_extract(payload, '$.{field}') = ?")
                more_params.append(value)
            has_more = (
                conn.execute(
                    f"SELECT 1 FROM {self._table} WHERE {' AND '.join(more_predicates)} LIMIT 1",
                    more_params,
                ).fetchone()
                is not None
            )
        return records, str(last_id), has_more

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

    def find_lineage(self, field: str, value: str, kind: LineageKind) -> list[dict]:
        """Return one logical lineage through the persistent expression index."""
        configured = _LINEAGE_FIELDS.get(self._table)
        if configured != (field, kind) or not _FIELD_RE.match(field):
            return []
        root = lineage_root(value, kind)
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"""
                SELECT payload FROM {self._table}
                WHERE {_LINEAGE_SQL_FUNCTION}(
                    json_extract(payload, '$.{field}'), '{kind}'
                ) = ?
                ORDER BY id DESC
                """,
                (root,),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def lineage_fingerprint(
        self,
        field: str,
        value: str,
        kind: LineageKind,
    ) -> tuple[int, int]:
        """Return (row_count, max_rowid) for one indexed logical lineage."""
        configured = _LINEAGE_FIELDS.get(self._table)
        if configured != (field, kind) or not _FIELD_RE.match(field):
            return (0, 0)
        root = lineage_root(value, kind)
        with closing(self._connect()) as conn:
            row = conn.execute(
                f"""
                SELECT COUNT(*), COALESCE(MAX(id), 0) FROM {self._table}
                WHERE {_LINEAGE_SQL_FUNCTION}(
                    json_extract(payload, '$.{field}'), '{kind}'
                ) = ?
                """,
                (root,),
            ).fetchone()
        return (int(row[0]), int(row[1])) if row else (0, 0)

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
