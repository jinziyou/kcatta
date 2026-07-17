"""Durable scan schedules (cron-like interval) owned by Form.

Schedules enqueue normal ScanJobs through the existing durable worker; they
do not bypass lease/cancel/retry semantics. Interval is wall-clock minutes
(simple and testable) rather than a full cron expression parser.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from analyzer.schemas.common import StrictModel, Timestamp
from pydantic import Field, field_validator

from .schemas.scan import ScanCapability, ScanJobOptions


class ScanSchedule(StrictModel):
    """A recurring scan plan for one target/capability."""

    schedule_id: str
    target_id: str
    capability: ScanCapability
    interval_minutes: int = Field(ge=1, le=60 * 24 * 30)
    enabled: bool = True
    options: ScanJobOptions = Field(default_factory=ScanJobOptions)
    created_at: Timestamp
    updated_at: Timestamp
    next_run_at: Timestamp
    last_job_id: str | None = None
    last_enqueued_at: Timestamp | None = None

    @field_validator("interval_minutes")
    @classmethod
    def _interval(cls, value: int) -> int:
        if value < 1:
            raise ValueError("interval_minutes must be >= 1")
        return value


class ScanScheduleInput(StrictModel):
    target_id: str
    capability: ScanCapability
    interval_minutes: int = Field(ge=1, le=60 * 24 * 30)
    enabled: bool = True
    options: ScanJobOptions = Field(default_factory=ScanJobOptions)


class ScheduleStore:
    """SQLite-backed schedule registry under FORM_DATA_DIR."""

    def __init__(self, data_dir: Path) -> None:
        self._path = Path(data_dir) / "form-schedules.db"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_schedules (
                schedule_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                next_run_at_us INTEGER NOT NULL,
                enabled INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def list(self) -> list[ScanSchedule]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM scan_schedules ORDER BY schedule_id"
            ).fetchall()
        return [ScanSchedule.model_validate_json(row["payload"]) for row in rows]

    def get(self, schedule_id: str) -> ScanSchedule | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM scan_schedules WHERE schedule_id=?",
                (schedule_id,),
            ).fetchone()
        if row is None:
            return None
        return ScanSchedule.model_validate_json(row["payload"])

    def create(self, body: ScanScheduleInput, now: datetime | None = None) -> ScanSchedule:
        now = _utc(now or datetime.now(UTC))
        schedule = ScanSchedule(
            schedule_id=f"sched-{uuid.uuid4().hex[:12]}",
            target_id=body.target_id,
            capability=body.capability,
            interval_minutes=body.interval_minutes,
            enabled=body.enabled,
            options=body.options,
            created_at=now,
            updated_at=now,
            next_run_at=now,
        )
        self._upsert(schedule)
        return schedule

    def delete(self, schedule_id: str) -> bool:
        with self._lock:
            changed = self._conn.execute(
                "DELETE FROM scan_schedules WHERE schedule_id=?",
                (schedule_id,),
            ).rowcount
            self._conn.commit()
        return changed == 1

    def due(self, now: datetime) -> list[ScanSchedule]:
        now = _utc(now)
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT payload FROM scan_schedules
                WHERE enabled=1 AND next_run_at_us <= ?
                ORDER BY next_run_at_us, schedule_id
                """,
                (_micros(now),),
            ).fetchall()
        return [ScanSchedule.model_validate_json(row["payload"]) for row in rows]

    def mark_enqueued(
        self,
        schedule: ScanSchedule,
        job_id: str,
        now: datetime,
    ) -> ScanSchedule:
        now = _utc(now)
        updated = schedule.model_copy(deep=True)
        updated.last_job_id = job_id
        updated.last_enqueued_at = now
        updated.updated_at = now
        updated.next_run_at = now + timedelta(minutes=updated.interval_minutes)
        self._upsert(updated)
        return updated

    def snooze(
        self,
        schedule: ScanSchedule,
        now: datetime,
        *,
        minutes: int | None = None,
    ) -> ScanSchedule:
        """Push next_run forward without recording a job (missing target, etc.)."""
        now = _utc(now)
        updated = schedule.model_copy(deep=True)
        updated.updated_at = now
        updated.next_run_at = now + timedelta(minutes=minutes or updated.interval_minutes)
        self._upsert(updated)
        return updated

    def _upsert(self, schedule: ScanSchedule) -> None:
        payload = schedule.model_dump_json()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scan_schedules (schedule_id, payload, next_run_at_us, enabled)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(schedule_id) DO UPDATE SET
                    payload=excluded.payload,
                    next_run_at_us=excluded.next_run_at_us,
                    enabled=excluded.enabled
                """,
                (
                    schedule.schedule_id,
                    payload,
                    _micros(schedule.next_run_at),
                    1 if schedule.enabled else 0,
                ),
            )
            self._conn.commit()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _micros(value: datetime | None) -> int | None:
    if value is None:
        return None
    value = _utc(value)
    return int(value.timestamp() * 1_000_000)
