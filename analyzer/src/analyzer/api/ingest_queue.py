"""Durable ingest idempotency ledger and recoverable derived-work queue.

The raw envelope payload is committed to this SQLite ledger before an async
ingest request is acknowledged.  A leased worker then copies the envelope into
the normal report store and runs detection/correlation.  Completed rows retain
only the payload digest and outcome, keeping durable deduplication cheap while
pending rows remain a bounded on-disk outbox.

The ledger is deliberately independent of ``ANALYZER_STORAGE``.  JSONL remains
useful for small single-process deployments, while this correctness-critical
state still needs atomic compare-and-set semantics across processes and restarts.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..storage import StorageCapacityError

logger = logging.getLogger(__name__)

DEFAULT_LEDGER_MAX_BYTES = 512 * 1024 * 1024
DEFAULT_LEASE_SECONDS = 30.0
DEFAULT_POLL_SECONDS = 0.25
DEFAULT_RETRY_BASE_SECONDS = 5.0
DEFAULT_RETRY_MAX_SECONDS = 300.0

TaskKind = Literal["asset-report", "trace-batch", "guard-event"]
TaskState = Literal["pending", "processing", "complete", "partial"]


class LedgerConflictError(ValueError):
    """An idempotency key was reused for a different payload."""


@dataclass(frozen=True)
class LedgerTask:
    key: str
    kind: TaskKind
    envelope_id: str
    payload: str
    payload_sha256: str
    state: TaskState
    attempts: int
    next_attempt_at: float
    lease_token: str | None
    derived_records: int
    derived_truncated: bool
    derived_reason: str | None
    last_error: str | None
    updated_at: float

    @property
    def final(self) -> bool:
        return self.state in {"complete", "partial"}


@dataclass(frozen=True)
class SubmitResult:
    task: LedgerTask
    created: bool


def _positive_float(name: str, default: float) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return value


def _nonnegative_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a non-negative integer") from exc
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


class IngestLedger:
    """SQLite compare-and-set ledger shared by every Analyzer worker process."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_completed: int,
        max_bytes: int | None = None,
    ) -> None:
        self.path = Path(path)
        self.max_completed = max(1, max_completed)
        self.max_bytes = (
            _nonnegative_int("ANALYZER_INGEST_LEDGER_MAX_BYTES", DEFAULT_LEDGER_MAX_BYTES)
            if max_bytes is None
            else max(0, max_bytes)
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = self._connect()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        # The ledger is the acknowledged async outbox, so prefer full commit
        # durability even when the larger reporting database uses NORMAL.
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @contextmanager
    def _connection(self):  # type: ignore[no-untyped-def]
        """Serialize local threads over one reusable WAL connection."""
        with self._lock:
            try:
                yield self._conn
            except Exception:
                if self._conn.in_transaction:
                    self._conn.rollback()
                raise

    def _ensure_schema(self) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ingest_tasks (
                    task_key TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    envelope_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    lease_until REAL,
                    lease_token TEXT,
                    derived_records INTEGER NOT NULL DEFAULT 0,
                    derived_truncated INTEGER NOT NULL DEFAULT 0,
                    derived_reason TEXT,
                    last_error TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    CHECK (kind IN ('asset-report', 'trace-batch', 'guard-event')),
                    CHECK (state IN ('pending', 'processing', 'complete', 'partial'))
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_ingest_tasks_due
                ON ingest_tasks (state, next_attempt_at, created_at)
                """
            )
            conn.commit()

    def _current_bytes(self) -> int:
        return sum(
            candidate.stat().st_size
            for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm"))
            if candidate.exists()
        )

    def _ensure_insert_budget(self, payload_bytes: int) -> None:
        if not self.max_bytes:
            return
        estimated_growth = payload_bytes * 2 + 64 * 1024
        # Clearing completed payloads frees pages for reuse without shrinking
        # the high-water file size. Count those freelist pages as available.
        page_size = int(self._conn.execute("PRAGMA page_size").fetchone()[0])
        reusable = int(self._conn.execute("PRAGMA freelist_count").fetchone()[0]) * page_size
        effective = max(0, self._current_bytes() - reusable)
        if effective + estimated_growth > self.max_bytes:
            raise StorageCapacityError(
                "durable ingest queue is full "
                f"({effective} effective bytes used, {self.max_bytes} configured)"
            )

    @staticmethod
    def _task(row: sqlite3.Row) -> LedgerTask:
        return LedgerTask(
            key=str(row["task_key"]),
            kind=str(row["kind"]),  # type: ignore[arg-type]
            envelope_id=str(row["envelope_id"]),
            payload=str(row["payload"]),
            payload_sha256=str(row["payload_sha256"]),
            state=str(row["state"]),  # type: ignore[arg-type]
            attempts=int(row["attempts"]),
            next_attempt_at=float(row["next_attempt_at"]),
            lease_token=str(row["lease_token"]) if row["lease_token"] else None,
            derived_records=int(row["derived_records"]),
            derived_truncated=bool(row["derived_truncated"]),
            derived_reason=str(row["derived_reason"]) if row["derived_reason"] else None,
            last_error=str(row["last_error"]) if row["last_error"] else None,
            updated_at=float(row["updated_at"]),
        )

    def submit(
        self,
        *,
        key: str,
        kind: TaskKind,
        envelope_id: str,
        payload: str,
    ) -> SubmitResult:
        """Durably reserve ``key`` or replay its existing task state."""
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        now = time.time()
        with self._connection() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM ingest_tasks WHERE task_key = ?", (key,)
                ).fetchone()
                if row is not None:
                    # A completed key is immutable and replays its outcome even
                    # across rolling schema upgrades whose canonical JSON may
                    # gain new defaulted fields. While work is pending, however,
                    # accepting different content would make the queued payload
                    # ambiguous and must fail closed.
                    if (
                        row["state"] not in {"complete", "partial"}
                        and row["payload_sha256"] != digest
                    ):
                        raise LedgerConflictError(
                            "idempotency key already belongs to a different payload"
                        )
                    conn.commit()
                    return SubmitResult(task=self._task(row), created=False)
                self._ensure_insert_budget(len(payload.encode("utf-8")))
                conn.execute(
                    """
                    INSERT INTO ingest_tasks (
                        task_key, kind, envelope_id, payload, payload_sha256,
                        state, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (key, kind, envelope_id, payload, digest, now, now),
                )
                row = conn.execute(
                    "SELECT * FROM ingest_tasks WHERE task_key = ?", (key,)
                ).fetchone()
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                if getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                    raise StorageCapacityError("durable ingest queue storage is full") from exc
                raise
        assert row is not None
        return SubmitResult(task=self._task(row), created=True)

    def get(self, key: str) -> LedgerTask | None:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM ingest_tasks WHERE task_key = ?", (key,)).fetchone()
        return self._task(row) if row is not None else None

    def lineage(
        self,
        *,
        kind: TaskKind,
        source: str,
        envelope_id: str,
    ) -> list[LedgerTask]:
        """Return every retained task belonging to one logical chunked envelope."""

        base_key = f"{kind}:{source}:{envelope_id}"
        escaped_prefix = (
            f"{base_key}::chunk-".replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM ingest_tasks
                WHERE task_key = ? OR task_key LIKE ? ESCAPE '\\'
                ORDER BY created_at ASC
                LIMIT 4096
                """,
                (base_key, f"{escaped_prefix}%"),
            ).fetchall()
        return [self._task(row) for row in rows]

    def claim(self, key: str, *, lease_seconds: float) -> LedgerTask | None:
        """Claim one specific due task, including an expired processing lease."""
        return self._claim(where="task_key = ?", params=(key,), lease_seconds=lease_seconds)

    def claim_next(self, *, lease_seconds: float) -> LedgerTask | None:
        """Claim the oldest due task for a background worker."""
        return self._claim(where="1 = 1", params=(), lease_seconds=lease_seconds)

    def _claim(
        self,
        *,
        where: str,
        params: tuple[object, ...],
        lease_seconds: float,
    ) -> LedgerTask | None:
        now = time.time()
        token = uuid.uuid4().hex
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                f"""
                SELECT * FROM ingest_tasks
                WHERE {where}
                  AND (
                    (state = 'pending' AND next_attempt_at <= ?)
                    OR (state = 'processing' AND COALESCE(lease_until, 0) <= ?)
                  )
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (*params, now, now),
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            conn.execute(
                """
                UPDATE ingest_tasks
                SET state = 'processing', attempts = attempts + 1,
                    lease_until = ?, lease_token = ?, updated_at = ?
                WHERE task_key = ?
                """,
                (now + lease_seconds, token, now, row["task_key"]),
            )
            claimed = conn.execute(
                "SELECT * FROM ingest_tasks WHERE task_key = ?", (row["task_key"],)
            ).fetchone()
            conn.commit()
        assert claimed is not None
        return self._task(claimed)

    def extend_lease(self, key: str, token: str, *, lease_seconds: float) -> bool:
        now = time.time()
        with self._connection() as conn:
            changed = conn.execute(
                """
                UPDATE ingest_tasks SET lease_until = ?, updated_at = ?
                WHERE task_key = ? AND state = 'processing' AND lease_token = ?
                """,
                (now + lease_seconds, now, key, token),
            ).rowcount
            conn.commit()
        return changed == 1

    def complete(
        self,
        key: str,
        token: str,
        *,
        status: Literal["complete", "partial"],
        records: int,
        truncated: bool,
        reason: str | None,
    ) -> bool:
        """Commit a final outcome and discard the now-redundant full payload."""
        now = time.time()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                """
                UPDATE ingest_tasks
                SET state = ?, payload = '', derived_records = ?,
                    derived_truncated = ?, derived_reason = ?, last_error = NULL,
                    lease_until = NULL, lease_token = NULL, updated_at = ?
                WHERE task_key = ? AND state = 'processing' AND lease_token = ?
                """,
                (status, records, int(truncated), reason, now, key, token),
            ).rowcount
            if changed:
                self._prune_completed(conn)
            conn.commit()
        return changed == 1

    def retry(
        self,
        key: str,
        token: str,
        *,
        reason: str,
        delay_seconds: float,
    ) -> bool:
        """Release a failed task back to the durable queue with backoff."""
        now = time.time()
        with self._connection() as conn:
            changed = conn.execute(
                """
                UPDATE ingest_tasks
                SET state = 'pending', next_attempt_at = ?, last_error = ?,
                    lease_until = NULL, lease_token = NULL, updated_at = ?
                WHERE task_key = ? AND state = 'processing' AND lease_token = ?
                """,
                (now + max(0.0, delay_seconds), reason[:2048], now, key, token),
            ).rowcount
            conn.commit()
        return changed == 1

    def _prune_completed(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            DELETE FROM ingest_tasks
            WHERE task_key IN (
                SELECT task_key FROM ingest_tasks
                WHERE state IN ('complete', 'partial')
                ORDER BY updated_at DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.max_completed,),
        )

    def counts(self) -> dict[str, int]:
        counts = {"pending": 0, "processing": 0, "complete": 0, "partial": 0}
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT state, COUNT(*) AS count FROM ingest_tasks GROUP BY state"
            ).fetchall()
        for row in rows:
            counts[str(row["state"])] = int(row["count"])
        return counts

    def close(self) -> None:
        """Close the process-local connection after the worker has stopped."""
        with self._lock:
            self._conn.close()


class DerivedWorker:
    """Single leased worker; multiple processes safely compete through SQLite."""

    def __init__(
        self,
        ledger: IngestLedger,
        processor: Callable[[LedgerTask], object],
        *,
        observer: Callable[[object], None] | None = None,
        lease_seconds: float | None = None,
        poll_seconds: float | None = None,
        retry_base_seconds: float | None = None,
        retry_max_seconds: float | None = None,
    ) -> None:
        self.ledger = ledger
        self.processor = processor
        self.observer = observer
        self.lease_seconds = lease_seconds or _positive_float(
            "ANALYZER_DERIVED_LEASE_SECONDS", DEFAULT_LEASE_SECONDS
        )
        self.poll_seconds = poll_seconds or _positive_float(
            "ANALYZER_DERIVED_POLL_SECONDS", DEFAULT_POLL_SECONDS
        )
        self.retry_base_seconds = retry_base_seconds or _positive_float(
            "ANALYZER_DERIVED_RETRY_BASE_SECONDS", DEFAULT_RETRY_BASE_SECONDS
        )
        self.retry_max_seconds = retry_max_seconds or _positive_float(
            "ANALYZER_DERIVED_RETRY_MAX_SECONDS", DEFAULT_RETRY_MAX_SECONDS
        )
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="analyzer-derived-worker",
            daemon=True,
        )
        self._thread.start()

    def notify(self) -> None:
        self._wake.set()

    def stop(self, timeout: float = 10.0) -> bool:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        return self._thread is None or not self._thread.is_alive()

    def _retry_delay(self, attempts: int) -> float:
        exponent = min(max(0, attempts - 1), 20)
        return min(self.retry_max_seconds, self.retry_base_seconds * (2**exponent))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                task = self.ledger.claim_next(lease_seconds=self.lease_seconds)
            except Exception:  # noqa: BLE001 - keep the durable worker alive
                logger.exception("derived worker could not claim a task")
                self._wake.wait(self.poll_seconds)
                self._wake.clear()
                continue
            if task is None:
                self._wake.wait(self.poll_seconds)
                self._wake.clear()
                continue
            try:
                self._process(task)
            except Exception:  # noqa: BLE001 - lease expiry makes replay safe
                logger.exception("derived worker loop failed for %s; lease will expire", task.key)

    def _process(self, task: LedgerTask) -> None:
        assert task.lease_token is not None
        heartbeat_stop = threading.Event()
        heartbeat = threading.Thread(
            target=self._heartbeat,
            args=(task, heartbeat_stop),
            name="analyzer-derived-lease",
            daemon=True,
        )
        heartbeat.start()
        try:
            outcome = self.processor(task)
        except Exception as exc:  # noqa: BLE001 - durable retry is the boundary
            logger.exception("derived task %s crashed; scheduling retry", task.key)
            self.ledger.retry(
                task.key,
                task.lease_token,
                reason=type(exc).__name__,
                delay_seconds=self._retry_delay(task.attempts),
            )
            return
        finally:
            heartbeat_stop.set()
            heartbeat.join(timeout=1.0)

        status = getattr(outcome, "status", "failed")
        if status == "failed":
            reason = str(getattr(outcome, "reason", None) or "derived_processing_failed")
            changed = self.ledger.retry(
                task.key,
                task.lease_token,
                reason=reason,
                delay_seconds=self._retry_delay(task.attempts),
            )
        else:
            changed = self.ledger.complete(
                task.key,
                task.lease_token,
                status=status,
                records=int(getattr(outcome, "records", 0)),
                truncated=bool(getattr(outcome, "truncated", False)),
                reason=getattr(outcome, "reason", None),
            )
        if changed and self.observer is not None:
            try:
                self.observer(outcome)
            except Exception:  # noqa: BLE001 - metrics must not kill the worker
                logger.exception("derived outcome observer failed for %s", task.key)

    def _heartbeat(self, task: LedgerTask, stop: threading.Event) -> None:
        assert task.lease_token is not None
        interval = max(0.05, self.lease_seconds / 3)
        while not stop.wait(interval):
            try:
                extended = self.ledger.extend_lease(
                    task.key,
                    task.lease_token,
                    lease_seconds=self.lease_seconds,
                )
            except Exception:  # noqa: BLE001 - main worker owns retry semantics
                logger.exception("derived lease heartbeat failed for %s", task.key)
                return
            if not extended:
                return
