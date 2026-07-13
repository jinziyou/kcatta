"""Transactional durable scan-job repository with lease fencing.

This is deliberately separate from the generic telemetry append stores. A
queue head is operational state and must never disappear because history
retention removed an old row. SQLite ``BEGIN IMMEDIATE`` serializes claim/CAS
transactions across Form processes sharing the same local database.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
from collections.abc import Callable, Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from analyzer.storage import StorageCapacityError

from .schemas import ScanCapability, ScanJob, ScanJobState

DEFAULT_DB_FILENAME = "form-jobs.db"
DEFAULT_MAX_DB_BYTES = 256 * 1024 * 1024
DEFAULT_WAL_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_RECORD_BYTES = 64 * 1024
DEFAULT_MAX_JOBS = 100_000
DEFAULT_MAX_HISTORY = 100_000
_TERMINAL = {
    ScanJobState.SUCCEEDED.value,
    ScanJobState.FAILED.value,
    ScanJobState.CANCELLED.value,
}
_ACTIVE = {ScanJobState.RUNNING.value, ScanJobState.CANCELLING.value}

_LOCKS_GUARD = threading.Lock()
_DB_LOCKS: dict[Path, threading.RLock] = {}


class JobStoreError(RuntimeError):
    """Base error for durable job coordination."""


class JobNotFoundError(JobStoreError):
    """The requested job does not exist."""


class JobConflictError(JobStoreError):
    """A state/idempotency precondition conflicts with the durable head."""


class LeaseLostError(JobStoreError):
    """The lease token/epoch no longer owns this execution generation."""


@dataclass(frozen=True)
class ClaimedScanJob:
    """Private execution capability; never serialized into the public API."""

    job: ScanJob
    lease_token: str
    lease_epoch: int
    lease_owner: str
    lease_expires_at: datetime


@dataclass(frozen=True)
class TargetOperationLease:
    """Fenced lease for a direct target mutation outside the durable job queue."""

    target_id: str
    lease_token: str
    lease_owner: str
    lease_expires_at: datetime


def _shared_lock(path: Path) -> threading.RLock:
    key = path.absolute()
    with _LOCKS_GUARD:
        return _DB_LOCKS.setdefault(key, threading.RLock())


def _limit(explicit: int | None, env_name: str, default: int) -> int:
    raw: int | str = explicit if explicit is not None else os.getenv(env_name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{env_name} must be a non-negative integer") from exc
    if value < 0:
        raise ValueError(f"{env_name} must be a non-negative integer")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _micros(value: datetime | None) -> int | None:
    return None if value is None else int(_utc(value).timestamp() * 1_000_000)


def _from_micros(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _sqlite_full(exc: sqlite3.Error) -> bool:
    return (
        getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL
        or "database or disk is full" in str(exc).lower()
    )


class ScanJobRepository:
    """One-row-per-job queue heads plus bounded, transactional event history."""

    def __init__(
        self,
        data_dir: Path,
        *,
        max_record_bytes: int | None = None,
        max_db_bytes: int | None = None,
        wal_max_bytes: int | None = None,
        max_jobs: int | None = None,
        max_history: int | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.db_path = data_dir / DEFAULT_DB_FILENAME
        self.max_record_bytes = _limit(
            max_record_bytes,
            "FORM_SCAN_JOB_MAX_RECORD_BYTES",
            DEFAULT_MAX_RECORD_BYTES,
        )
        self.max_db_bytes = _limit(
            max_db_bytes,
            "FORM_SCAN_JOB_DB_MAX_BYTES",
            DEFAULT_MAX_DB_BYTES,
        )
        self.wal_max_bytes = _limit(
            wal_max_bytes,
            "FORM_SCAN_JOB_WAL_MAX_BYTES",
            DEFAULT_WAL_MAX_BYTES,
        )
        self.max_jobs = _limit(max_jobs, "FORM_SCAN_JOB_MAX_ROWS", DEFAULT_MAX_JOBS)
        self.max_history = _limit(
            max_history,
            "FORM_SCAN_JOB_HISTORY_MAX_ROWS",
            DEFAULT_MAX_HISTORY,
        )
        if self.max_db_bytes and self.wal_max_bytes >= self.max_db_bytes:
            raise ValueError("FORM_SCAN_JOB_WAL_MAX_BYTES must be smaller than the DB budget")
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._lock = _shared_lock(self.db_path)
        self._closed = False
        self._ensure_schema()

    def _connect(
        self,
        *,
        write: bool = False,
        configure_journal: bool = False,
    ) -> sqlite3.Connection:
        if self._closed:
            raise RuntimeError("scan-job repository is closed")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            self.db_path,
            timeout=5,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        # journal_mode is persistent database metadata. Re-requesting WAL on
        # every read connection can need a schema lock and starve lease
        # heartbeats under a busy polling API. Configure it once at repository
        # initialization; keep the connection-local safety settings here.
        if configure_journal:
            connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        if write:
            connection.execute("PRAGMA synchronous=FULL")
        if configure_journal and self.wal_max_bytes:
            connection.execute(f"PRAGMA journal_size_limit={self.wal_max_bytes}")
        if write and self.wal_max_bytes:
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            pages = max(1, min(1000, self.wal_max_bytes // page_size // 2))
            connection.execute(f"PRAGMA wal_autocheckpoint={pages}")
        return connection

    def _ensure_schema(self) -> None:
        with self._lock:
            connection = self._connect(write=True, configure_journal=True)
            try:
                self._apply_page_budget(connection)
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS scan_job_heads (
                        job_id TEXT PRIMARY KEY,
                        payload TEXT NOT NULL,
                        payload_bytes INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        target_id TEXT NOT NULL,
                        created_at_us INTEGER NOT NULL,
                        updated_at_us INTEGER NOT NULL,
                        available_at_us INTEGER,
                        attempt INTEGER NOT NULL,
                        max_attempts INTEGER NOT NULL,
                        revision INTEGER NOT NULL,
                        lease_owner TEXT,
                        lease_token_hash TEXT,
                        lease_epoch INTEGER NOT NULL DEFAULT 0,
                        lease_expires_at_us INTEGER,
                        heartbeat_at_us INTEGER,
                        idempotency_key TEXT UNIQUE,
                        request_fingerprint TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_scan_job_heads_claim
                        ON scan_job_heads(state, available_at_us, created_at_us);
                    CREATE INDEX IF NOT EXISTS idx_scan_job_heads_lease
                        ON scan_job_heads(state, lease_expires_at_us);
                    CREATE INDEX IF NOT EXISTS idx_scan_job_heads_updated
                        ON scan_job_heads(updated_at_us DESC, job_id);
                    CREATE INDEX IF NOT EXISTS idx_scan_job_heads_target_lease
                        ON scan_job_heads(target_id, state, lease_expires_at_us);
                    CREATE TABLE IF NOT EXISTS target_operation_leases (
                        target_id TEXT PRIMARY KEY,
                        lease_owner TEXT NOT NULL,
                        lease_token_hash TEXT NOT NULL,
                        lease_expires_at_us INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_target_operation_leases_expiry
                        ON target_operation_leases(lease_expires_at_us);
                    CREATE TABLE IF NOT EXISTS scan_job_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        at_us INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        payload_bytes INTEGER NOT NULL,
                        UNIQUE(job_id, revision)
                    );
                    CREATE INDEX IF NOT EXISTS idx_scan_job_events_job
                        ON scan_job_events(job_id, revision DESC);
                    """
                )
            finally:
                connection.close()

    def _apply_page_budget(self, connection: sqlite3.Connection) -> None:
        if not self.max_db_bytes:
            return
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        reserve = self.wal_max_bytes + 32 * 1024
        usable = self.max_db_bytes - reserve
        if usable < page_size * 4:
            raise ValueError("scan-job DB budget leaves too little space after WAL reserve")
        page_limit = usable // page_size
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_count > page_limit:
            raise StorageCapacityError(
                "existing scan-job database exceeds FORM_SCAN_JOB_DB_MAX_BYTES"
            )
        connection.execute(f"PRAGMA max_page_count={page_limit}")

    @contextmanager
    def _transaction(self):  # type: ignore[no-untyped-def]
        with self._lock:
            connection = self._connect(write=True)
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except sqlite3.Error as exc:
                connection.rollback()
                if _sqlite_full(exc):
                    raise StorageCapacityError("scan-job database is full") from exc
                raise
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def _encode(self, job: ScanJob) -> tuple[ScanJob, str, int]:
        validated = ScanJob.model_validate(job.model_dump(mode="python"))
        payload = validated.model_dump_json()
        payload_bytes = len(payload.encode("utf-8"))
        if self.max_record_bytes and payload_bytes > self.max_record_bytes:
            raise StorageCapacityError(
                f"scan job {job.job_id} exceeds {self.max_record_bytes} bytes"
            )
        return validated, payload, payload_bytes

    def _event(
        self,
        connection: sqlite3.Connection,
        job: ScanJob,
        revision: int,
        at: datetime,
        payload: str,
        payload_bytes: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO scan_job_events
                (job_id, revision, state, at_us, payload, payload_bytes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (job.job_id, revision, job.state.value, _micros(at), payload, payload_bytes),
        )
        if self.max_history:
            count = int(connection.execute("SELECT COUNT(*) FROM scan_job_events").fetchone()[0])
            overflow = count - self.max_history
            if overflow > 0:
                connection.execute(
                    "DELETE FROM scan_job_events WHERE id IN "
                    "(SELECT id FROM scan_job_events ORDER BY id ASC LIMIT ?)",
                    (overflow,),
                )

    def _make_room_for_job(self, connection: sqlite3.Connection) -> None:
        if not self.max_jobs:
            return
        count = int(connection.execute("SELECT COUNT(*) FROM scan_job_heads").fetchone()[0])
        if count < self.max_jobs:
            return
        low_water = max(0, self.max_jobs - max(1, self.max_jobs // 10))
        remove = count - low_water
        rows = connection.execute(
            """
            SELECT job_id FROM scan_job_heads
            WHERE state IN ('succeeded', 'failed', 'cancelled')
            ORDER BY updated_at_us ASC, job_id ASC
            LIMIT ?
            """,
            (remove,),
        ).fetchall()
        if not rows:
            raise StorageCapacityError(
                "scan-job capacity is occupied by active jobs; refusing to evict them"
            )
        connection.executemany(
            "DELETE FROM scan_job_heads WHERE job_id = ?",
            [(str(row["job_id"]),) for row in rows],
        )

    def create(
        self,
        job: ScanJob,
        *,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None,
    ) -> tuple[ScanJob, bool]:
        """Create a pending head, or replay an identical idempotent request."""
        job, payload, payload_bytes = self._encode(job)
        if idempotency_key is not None:
            idempotency_key = idempotency_key.strip()
            if not idempotency_key or len(idempotency_key) > 256:
                raise ValueError("Idempotency-Key must contain 1..256 characters")
            if not request_fingerprint:
                raise ValueError("idempotent create requires a request fingerprint")
        with self._transaction() as connection:
            if idempotency_key is not None:
                existing = connection.execute(
                    "SELECT payload, request_fingerprint FROM scan_job_heads "
                    "WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    if existing["request_fingerprint"] != request_fingerprint:
                        raise JobConflictError(
                            "Idempotency-Key was already used for a different scan request"
                        )
                    return ScanJob.model_validate_json(existing["payload"]), False
            if connection.execute(
                "SELECT 1 FROM scan_job_heads WHERE job_id = ?", (job.job_id,)
            ).fetchone():
                raise JobConflictError(f"scan job already exists: {job.job_id}")
            self._make_room_for_job(connection)
            created_at = _micros(job.created_at)
            updated_at = _micros(job.updated_at or job.created_at)
            connection.execute(
                """
                INSERT INTO scan_job_heads (
                    job_id, payload, payload_bytes, state, target_id,
                    created_at_us, updated_at_us, available_at_us,
                    attempt, max_attempts, revision, lease_epoch,
                    idempotency_key, request_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
                """,
                (
                    job.job_id,
                    payload,
                    payload_bytes,
                    job.state.value,
                    job.target_id,
                    created_at,
                    updated_at,
                    _micros(job.available_at),
                    job.attempt,
                    job.max_attempts,
                    idempotency_key,
                    request_fingerprint,
                ),
            )
            self._event(
                connection,
                job,
                0,
                job.updated_at or job.created_at,
                payload,
                payload_bytes,
            )
        return job, True

    def get(self, job_id: str) -> ScanJob | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT payload FROM scan_job_heads WHERE job_id = ?", (job_id,)
            ).fetchone()
        finally:
            connection.close()
        return ScanJob.model_validate_json(row["payload"]) if row else None

    def list(
        self,
        limit: int = 1_000,
        states: Sequence[ScanJobState] | None = None,
    ) -> list[ScanJob]:
        if limit <= 0:
            return []
        connection = self._connect()
        try:
            if states:
                placeholders = ",".join("?" for _ in states)
                rows = connection.execute(
                    f"SELECT payload FROM scan_job_heads WHERE state IN ({placeholders}) "
                    "ORDER BY created_at_us DESC, job_id DESC LIMIT ?",
                    (*[state.value for state in states], limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT payload FROM scan_job_heads "
                    "ORDER BY created_at_us DESC, job_id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        finally:
            connection.close()
        return [ScanJob.model_validate_json(row["payload"]) for row in rows]

    def _fail_exhausted(self, connection: sqlite3.Connection, now: datetime) -> None:
        rows = connection.execute(
            """
            SELECT * FROM scan_job_heads
            WHERE attempt >= max_attempts
              AND state IN ('pending', 'retrying')
              AND (available_at_us IS NULL OR available_at_us <= ?)
            """,
            (_micros(now),),
        ).fetchall()
        for row in rows:
            job = ScanJob.model_validate_json(row["payload"])
            job.state = ScanJobState.FAILED
            job.error = "scan exhausted its configured execution attempts"
            job.available_at = None
            job.finished_at = now
            job.updated_at = now
            job, payload, payload_bytes = self._encode(job)
            revision = int(row["revision"]) + 1
            connection.execute(
                """
                UPDATE scan_job_heads SET
                    payload=?, payload_bytes=?, state=?, updated_at_us=?,
                    available_at_us=NULL, revision=?,
                    lease_owner=NULL, lease_token_hash=NULL,
                    lease_expires_at_us=NULL, heartbeat_at_us=NULL
                WHERE job_id=? AND revision=?
                """,
                (
                    payload,
                    payload_bytes,
                    job.state.value,
                    _micros(now),
                    revision,
                    job.job_id,
                    int(row["revision"]),
                ),
            )
            self._event(connection, job, revision, now, payload, payload_bytes)

    def claim_next(
        self,
        worker_id: str,
        now: datetime,
        lease_ttl: timedelta,
        max_running: int,
        exclude_job_ids: Sequence[str] = (),
    ) -> ClaimedScanJob | None:
        if not worker_id or max_running <= 0 or lease_ttl.total_seconds() <= 0:
            raise ValueError("claim requires worker_id, positive ttl and max_running")
        now = _utc(now)
        with self._transaction() as connection:
            self._fail_exhausted(connection, now)
            connection.execute(
                "DELETE FROM target_operation_leases WHERE lease_expires_at_us <= ?",
                (_micros(now),),
            )
            active = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM scan_job_heads
                    WHERE state IN ('running', 'cancelling')
                      AND lease_expires_at_us > ?
                    """,
                    (_micros(now),),
                ).fetchone()[0]
            )
            if active >= max_running:
                return None
            exclusions = tuple(dict.fromkeys(exclude_job_ids))
            exclusion_sql = ""
            parameters: list[int | str] = [
                _micros(now),
                _micros(now),
                _micros(now),
                _micros(now),
                _micros(now),
            ]
            if exclusions:
                placeholders = ",".join("?" for _ in exclusions)
                exclusion_sql = f" AND candidate.job_id NOT IN ({placeholders})"
                parameters.extend(exclusions)
            row = connection.execute(
                f"""
                SELECT candidate.* FROM scan_job_heads AS candidate
                WHERE ((
                    candidate.state IN ('pending', 'retrying')
                    AND candidate.attempt < candidate.max_attempts
                    AND (candidate.available_at_us IS NULL OR candidate.available_at_us <= ?)
                ) OR (
                    candidate.state = 'running'
                    AND (
                        candidate.lease_expires_at_us IS NULL
                        OR candidate.lease_expires_at_us <= ?
                    )
                ) OR (
                    candidate.state = 'cancelling'
                    AND (
                        candidate.lease_expires_at_us IS NULL
                        OR candidate.lease_expires_at_us <= ?
                    )
                ))
                AND NOT EXISTS (
                    SELECT 1 FROM scan_job_heads AS active_target
                    WHERE active_target.target_id = candidate.target_id
                      AND active_target.job_id != candidate.job_id
                      AND active_target.state IN ('running', 'cancelling')
                      AND active_target.lease_expires_at_us > ?
                )
                AND NOT EXISTS (
                    SELECT 1 FROM target_operation_leases AS direct_target
                    WHERE direct_target.target_id = candidate.target_id
                      AND direct_target.lease_expires_at_us > ?
                ){exclusion_sql}
                ORDER BY
                    CASE candidate.state
                        WHEN 'cancelling' THEN 0
                        WHEN 'running' THEN 1
                        ELSE 2
                    END,
                    COALESCE(candidate.available_at_us, candidate.created_at_us),
                    candidate.created_at_us,
                    candidate.job_id
                LIMIT 1
                """,
                parameters,
            ).fetchone()
            if row is None:
                return None

            job = ScanJob.model_validate_json(row["payload"])
            if job.state != ScanJobState.CANCELLING:
                reconciliation_only = (
                    job.state == ScanJobState.RUNNING and job.attempt >= job.max_attempts
                )
                job.state = ScanJobState.RUNNING
                # An expired final execution still needs a fenced owner: HOST /
                # TRACE may have a durable spool artifact to hand off, while a
                # Guard may need to join its remote manifest. This extra claim
                # is reconciliation-only and remains capped so repeated crashes
                # or an uncertain remote outcome cannot grow public metadata
                # without bound.
                job.attempt = job.max_attempts + 1 if reconciliation_only else job.attempt + 1
                job.started_at = job.started_at or now
                job.available_at = None
                job.error = None
            job.updated_at = now
            job, payload, payload_bytes = self._encode(job)
            token = self._token_factory()
            if not token:
                raise RuntimeError("lease token factory returned an empty token")
            epoch = int(row["lease_epoch"]) + 1
            revision = int(row["revision"]) + 1
            expires = now + lease_ttl
            changed = connection.execute(
                """
                UPDATE scan_job_heads SET
                    payload=?, payload_bytes=?, state=?, updated_at_us=?,
                    available_at_us=?, attempt=?, max_attempts=?, revision=?,
                    lease_owner=?, lease_token_hash=?, lease_epoch=?,
                    lease_expires_at_us=?, heartbeat_at_us=?
                WHERE job_id=? AND revision=?
                """,
                (
                    payload,
                    payload_bytes,
                    job.state.value,
                    _micros(now),
                    _micros(job.available_at),
                    job.attempt,
                    job.max_attempts,
                    revision,
                    worker_id,
                    _token_hash(token),
                    epoch,
                    _micros(expires),
                    _micros(now),
                    job.job_id,
                    int(row["revision"]),
                ),
            ).rowcount
            if changed != 1:
                return None
            self._event(connection, job, revision, now, payload, payload_bytes)
        return ClaimedScanJob(job, token, epoch, worker_id, expires)

    def acquire_target_operation(
        self,
        target_id: str,
        owner: str,
        now: datetime,
        lease_ttl: timedelta,
    ) -> TargetOperationLease | None:
        """Serialize a direct deploy/stop mutation with durable target jobs.

        The same ``BEGIN IMMEDIATE`` transaction used by :meth:`claim_next`
        closes the check-vs-claim race across Form processes. A crashed API
        process leaves only a bounded lease, never a permanent target lock.
        """

        target_id = target_id.strip()
        owner = owner.strip()
        if not target_id or not owner or lease_ttl.total_seconds() <= 0:
            raise ValueError("target operation requires target_id, owner and positive ttl")
        if len(owner) > 256:
            raise ValueError("target operation owner exceeds 256 characters")
        now = _utc(now)
        expires = now + lease_ttl
        with self._transaction() as connection:
            connection.execute(
                "DELETE FROM target_operation_leases WHERE lease_expires_at_us <= ?",
                (_micros(now),),
            )
            active = connection.execute(
                """
                SELECT 1 FROM scan_job_heads
                WHERE target_id = ?
                  AND state IN ('running', 'cancelling')
                  AND lease_expires_at_us > ?
                LIMIT 1
                """,
                (target_id, _micros(now)),
            ).fetchone()
            if active is not None:
                return None
            token = self._token_factory()
            if not token:
                raise RuntimeError("lease token factory returned an empty token")
            try:
                connection.execute(
                    """
                    INSERT INTO target_operation_leases (
                        target_id, lease_owner, lease_token_hash, lease_expires_at_us
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (target_id, owner, _token_hash(token), _micros(expires)),
                )
            except sqlite3.IntegrityError:
                return None
            # Acquiring the direct-operation generation is also the durable
            # fence for workers whose job lease already expired. Clearing the
            # old capability prevents a worker with a regressed wall clock
            # from reviving it after the direct operation has been released.
            connection.execute(
                """
                UPDATE scan_job_heads
                SET lease_owner = NULL,
                    lease_token_hash = NULL,
                    lease_epoch = lease_epoch + 1,
                    lease_expires_at_us = NULL,
                    heartbeat_at_us = NULL
                WHERE target_id = ?
                  AND state IN ('running', 'cancelling')
                  AND (lease_expires_at_us IS NULL OR lease_expires_at_us <= ?)
                """,
                (target_id, _micros(now)),
            )
        return TargetOperationLease(target_id, token, owner, expires)

    def release_target_operation(self, lease: TargetOperationLease) -> None:
        """Release only the exact direct-operation capability that was acquired."""

        with self._transaction() as connection:
            removed = connection.execute(
                """
                DELETE FROM target_operation_leases
                WHERE target_id = ? AND lease_owner = ? AND lease_token_hash = ?
                """,
                (
                    lease.target_id,
                    lease.lease_owner,
                    _token_hash(lease.lease_token),
                ),
            ).rowcount
            if removed != 1:
                raise LeaseLostError(f"target operation lease lost for target {lease.target_id}")

    def renew_target_operation(
        self,
        lease: TargetOperationLease,
        now: datetime,
        lease_ttl: timedelta,
    ) -> TargetOperationLease:
        """Extend an unexpired direct-operation lease without reviving stale owners."""

        if lease_ttl.total_seconds() <= 0:
            raise ValueError("target operation renewal requires a positive ttl")
        now = _utc(now)
        expires = now + lease_ttl
        with self._transaction() as connection:
            changed = connection.execute(
                """
                UPDATE target_operation_leases
                SET lease_expires_at_us = ?
                WHERE target_id = ? AND lease_owner = ? AND lease_token_hash = ?
                  AND lease_expires_at_us > ?
                """,
                (
                    _micros(expires),
                    lease.target_id,
                    lease.lease_owner,
                    _token_hash(lease.lease_token),
                    _micros(now),
                ),
            ).rowcount
            if changed != 1:
                raise LeaseLostError(f"target operation lease lost for target {lease.target_id}")
        return TargetOperationLease(
            lease.target_id,
            lease.lease_token,
            lease.lease_owner,
            expires,
        )

    def _leased_row(
        self,
        connection: sqlite3.Connection,
        claim: ClaimedScanJob,
        now: datetime,
    ) -> sqlite3.Row:
        now_us = _micros(now)
        row = connection.execute(
            """
            SELECT leased.* FROM scan_job_heads AS leased
            WHERE leased.job_id=?
              AND leased.lease_owner=?
              AND leased.lease_token_hash=?
              AND leased.lease_epoch=?
              AND leased.state IN ('running', 'cancelling')
              AND leased.lease_expires_at_us > ?
              AND (leased.heartbeat_at_us IS NULL OR leased.heartbeat_at_us <= ?)
              AND NOT EXISTS (
                  SELECT 1 FROM target_operation_leases AS direct_target
                  WHERE direct_target.target_id = leased.target_id
                    AND direct_target.lease_expires_at_us > ?
              )
            """,
            (
                claim.job.job_id,
                claim.lease_owner,
                _token_hash(claim.lease_token),
                claim.lease_epoch,
                now_us,
                now_us,
                now_us,
            ),
        ).fetchone()
        if row is None:
            raise LeaseLostError(f"lease lost for scan job {claim.job.job_id}")
        return row

    def renew(
        self,
        claim: ClaimedScanJob,
        now: datetime,
        lease_ttl: timedelta,
    ) -> ClaimedScanJob:
        if lease_ttl.total_seconds() <= 0:
            raise ValueError("lease ttl must be positive")
        now = _utc(now)
        expires = now + lease_ttl
        with self._transaction() as connection:
            row = self._leased_row(connection, claim, now)
            changed = connection.execute(
                """
                UPDATE scan_job_heads
                SET lease_expires_at_us=?, heartbeat_at_us=?
                WHERE job_id=? AND lease_owner=? AND lease_token_hash=? AND lease_epoch=?
                """,
                (
                    _micros(expires),
                    _micros(now),
                    claim.job.job_id,
                    claim.lease_owner,
                    _token_hash(claim.lease_token),
                    claim.lease_epoch,
                ),
            ).rowcount
            if changed != 1:  # pragma: no cover - BEGIN IMMEDIATE makes this defensive
                raise LeaseLostError(f"lease lost for scan job {claim.job.job_id}")
            job = ScanJob.model_validate_json(row["payload"])
        return ClaimedScanJob(job, claim.lease_token, claim.lease_epoch, claim.lease_owner, expires)

    def complete(
        self,
        claim: ClaimedScanJob,
        updated_job: ScanJob,
        *,
        now: datetime | None = None,
    ) -> ScanJob:
        job, payload, payload_bytes = self._encode(updated_job)
        if job.job_id != claim.job.job_id:
            raise ValueError("cannot complete a lease with a different job_id")
        if job.state in {ScanJobState.PENDING, ScanJobState.RUNNING, ScanJobState.CANCELLING}:
            raise ValueError(f"invalid leased completion state: {job.state.value}")
        operation_at = _utc(now or datetime.now(UTC))
        at = job.updated_at or operation_at
        with self._transaction() as connection:
            row = self._leased_row(connection, claim, operation_at)
            cancellation_terminal = job.state in {
                ScanJobState.CANCELLED,
                ScanJobState.FAILED,
            }
            acknowledged_result = (
                job.state == ScanJobState.SUCCEEDED
                and job.result is not None
                and job.capability != ScanCapability.GUARD
            )
            if (
                row["state"] == ScanJobState.CANCELLING.value
                and not cancellation_terminal
                and not acknowledged_result
            ):
                raise LeaseLostError("cancellation won the completion race")
            revision = int(row["revision"]) + 1
            connection.execute(
                """
                UPDATE scan_job_heads SET
                    payload=?, payload_bytes=?, state=?, updated_at_us=?,
                    available_at_us=?, attempt=?, max_attempts=?, revision=?,
                    lease_owner=NULL, lease_token_hash=NULL,
                    lease_expires_at_us=NULL, heartbeat_at_us=NULL
                WHERE job_id=? AND lease_token_hash=? AND lease_epoch=?
                """,
                (
                    payload,
                    payload_bytes,
                    job.state.value,
                    _micros(at),
                    _micros(job.available_at),
                    job.attempt,
                    job.max_attempts,
                    revision,
                    job.job_id,
                    _token_hash(claim.lease_token),
                    claim.lease_epoch,
                ),
            )
            self._event(connection, job, revision, at, payload, payload_bytes)
        return job

    def request_cancel(self, job_id: str, now: datetime) -> ScanJob:
        now = _utc(now)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM scan_job_heads WHERE job_id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise JobNotFoundError(f"scan job not found: {job_id}")
            job = ScanJob.model_validate_json(row["payload"])
            if job.state in {
                ScanJobState.SUCCEEDED,
                ScanJobState.FAILED,
                ScanJobState.CANCELLED,
                ScanJobState.CANCELLING,
            }:
                return job
            job.cancel_requested_at = now
            job.updated_at = now
            if job.state in {ScanJobState.PENDING, ScanJobState.RETRYING}:
                job.state = ScanJobState.CANCELLED
                job.finished_at = now
                job.available_at = None
                job.error = "scan cancelled by operator"
            else:
                job.state = ScanJobState.CANCELLING
            job, payload, payload_bytes = self._encode(job)
            revision = int(row["revision"]) + 1
            connection.execute(
                """
                UPDATE scan_job_heads SET payload=?, payload_bytes=?, state=?,
                    updated_at_us=?, available_at_us=?, revision=?
                WHERE job_id=? AND revision=?
                """,
                (
                    payload,
                    payload_bytes,
                    job.state.value,
                    _micros(now),
                    _micros(job.available_at),
                    revision,
                    job_id,
                    int(row["revision"]),
                ),
            )
            self._event(connection, job, revision, now, payload, payload_bytes)
        return job

    def manual_retry(self, job_id: str, now: datetime) -> ScanJob:
        now = _utc(now)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM scan_job_heads WHERE job_id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise JobNotFoundError(f"scan job not found: {job_id}")
            job = ScanJob.model_validate_json(row["payload"])
            if job.state not in {ScanJobState.FAILED, ScanJobState.CANCELLED}:
                raise JobConflictError("only failed or cancelled scan jobs can be retried")
            job.state = ScanJobState.PENDING
            job.attempt = 0
            job.available_at = now
            job.updated_at = now
            job.started_at = None
            job.finished_at = None
            job.cancel_requested_at = None
            job.result = None
            job.error = None
            job, payload, payload_bytes = self._encode(job)
            revision = int(row["revision"]) + 1
            connection.execute(
                """
                UPDATE scan_job_heads SET payload=?, payload_bytes=?, state=?,
                    updated_at_us=?, available_at_us=?, attempt=?, revision=?,
                    lease_owner=NULL, lease_token_hash=NULL,
                    lease_expires_at_us=NULL, heartbeat_at_us=NULL
                WHERE job_id=? AND revision=?
                """,
                (
                    payload,
                    payload_bytes,
                    job.state.value,
                    _micros(now),
                    _micros(job.available_at),
                    job.attempt,
                    revision,
                    job_id,
                    int(row["revision"]),
                ),
            )
            self._event(connection, job, revision, now, payload, payload_bytes)
        return job

    def import_legacy(self, jobs: Iterable[ScanJob | dict], now: datetime) -> int:
        """Idempotently import latest legacy heads; unknown in-flight work fails safe."""
        imported = 0
        for value in jobs:
            try:
                job = value if isinstance(value, ScanJob) else ScanJob.model_validate(value)
            except Exception:  # noqa: BLE001 - one corrupt legacy row must not block startup
                continue
            if self.get(job.job_id) is not None:
                continue
            if job.state in {ScanJobState.RUNNING, ScanJobState.CANCELLING}:
                job.state = ScanJobState.FAILED
                job.error = "legacy Form stopped while this job was in-flight"
                job.finished_at = now
                job.available_at = None
                job.updated_at = now
            try:
                _, created = self.create(job)
            except JobConflictError:
                continue
            imported += int(created)
        return imported

    # Compatibility read adapters used while callers migrate off append stores.
    def tail(self, limit: int) -> list[dict]:
        return [job.model_dump(mode="json") for job in self.list(limit)]

    def find_one(self, field: str, value: str) -> dict | None:
        if field != "job_id":
            return None
        job = self.get(value)
        return job.model_dump(mode="json") if job else None

    def history(self, job_id: str, limit: int = 100) -> list[ScanJob]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT payload FROM scan_job_events WHERE job_id=? ORDER BY revision DESC LIMIT ?",
                (job_id, max(0, limit)),
            ).fetchall()
        finally:
            connection.close()
        return [ScanJob.model_validate_json(row["payload"]) for row in rows]

    def fingerprint(self) -> tuple[int, int]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(revision), 0) FROM scan_job_heads"
            ).fetchone()
        finally:
            connection.close()
        return (int(row[0]), int(row[1]))

    def retains_artifact(self, job_id: str) -> bool:
        """Whether a durable spool artifact may still be needed by this head."""
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT state FROM scan_job_heads WHERE job_id = ?", (job_id,)
            ).fetchone()
        finally:
            connection.close()
        return row is not None and str(row["state"]) in {
            ScanJobState.PENDING.value,
            ScanJobState.RETRYING.value,
            ScanJobState.RUNNING.value,
            ScanJobState.CANCELLING.value,
        }

    def close(self) -> None:
        self._closed = True


__all__ = [
    "ClaimedScanJob",
    "JobConflictError",
    "JobNotFoundError",
    "JobStoreError",
    "LeaseLostError",
    "ScanJobRepository",
    "TargetOperationLease",
]
