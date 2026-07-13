"""Offline migration of legacy Analyzer-owned scan control state into Form.

Only the two former control-plane stores are read: ``scan_targets`` and
``scan_jobs``.  Analyzer telemetry and analysis tables are deliberately outside
this module's allow-list, so they can never be copied by this migration.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from .schemas import ScanJob, ScanJobState, ScanTarget
from .storage import create_form_store

SourceStorage = Literal["auto", "jsonl", "sqlite"]
FormStorage = Literal["jsonl", "sqlite"]

_JSONL_FILES = {
    "targets": "scan-targets.jsonl",
    "jobs": "scan-jobs.jsonl",
}
_SQLITE_TABLES = {
    "targets": "scan_targets",
    "jobs": "scan_jobs",
}
_SQLITE_NAME = "analyzer.db"
_IN_FLIGHT_STATES = frozenset({ScanJobState.PENDING, ScanJobState.RUNNING})
MIGRATED_IN_FLIGHT_ERROR = (
    "Migrated from legacy Analyzer while the job was in-flight; rerun it from Form"
)


class ControlStateMigrationError(ValueError):
    """The legacy source is missing, ambiguous, corrupt, or incompatible."""


class _RecordStore(Protocol):
    def append(self, record: BaseModel) -> None: ...

    def find_one(self, field: str, value: str) -> dict | None: ...


@dataclass(frozen=True)
class ControlStateMigrationResult:
    """Counts emitted by one migration run."""

    source_storage: FormStorage
    target_rows_read: int
    unique_targets: int
    targets_migrated: int
    targets_skipped: int
    job_rows_read: int
    unique_jobs: int
    jobs_migrated: int
    jobs_skipped: int
    in_flight_jobs_failed: int


def _decode_payload(text: str, location: str) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ControlStateMigrationError(f"{location}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ControlStateMigrationError(f"{location}: expected a JSON object")
    return value


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records: list[dict] = []
    try:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                text = line.strip()
                if text:
                    records.append(_decode_payload(text, f"{path}:{line_number}"))
    except OSError as exc:
        raise ControlStateMigrationError(f"cannot read {path}: {exc}") from exc
    return records


def _sqlite_control_tables(path: Path) -> dict[str, int]:
    """Return recognized table row counts without creating or changing the DB."""

    if not path.exists():
        return {}
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            return {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in _SQLITE_TABLES.values()
                if table in tables
            }
    except sqlite3.Error as exc:
        raise ControlStateMigrationError(
            f"cannot inspect legacy SQLite database {path}: {exc}"
        ) from exc


def _read_sqlite(path: Path, table: str) -> list[dict]:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            rows = connection.execute(f"SELECT id, payload FROM {table} ORDER BY id ASC").fetchall()
    except sqlite3.Error as exc:
        raise ControlStateMigrationError(f"cannot read {path}:{table}: {exc}") from exc
    return [
        _decode_payload(str(payload), f"{path}:{table}:row {row_id}") for row_id, payload in rows
    ]


def _resolve_source_storage(data_dir: Path, requested: SourceStorage) -> FormStorage:
    sqlite_path = data_dir / _SQLITE_NAME
    sqlite_tables = _sqlite_control_tables(sqlite_path)
    jsonl_paths = [data_dir / name for name in _JSONL_FILES.values()]
    jsonl_present = any(path.exists() for path in jsonl_paths)
    jsonl_nonempty = any(path.exists() and path.stat().st_size > 0 for path in jsonl_paths)

    if requested == "sqlite":
        if not sqlite_tables:
            raise ControlStateMigrationError(
                f"{sqlite_path} has no legacy scan_targets/scan_jobs tables"
            )
        return "sqlite"
    if requested == "jsonl":
        if not jsonl_present:
            names = ", ".join(_JSONL_FILES.values())
            raise ControlStateMigrationError(f"{data_dir} has none of the legacy files: {names}")
        return "jsonl"

    # Old `analyzer-migrate-storage` left JSONL files next to the active SQLite
    # database. Prefer SQLite whenever it contains control rows; otherwise use a
    # populated JSONL source before accepting an empty recognized store.
    if sum(sqlite_tables.values()) > 0:
        return "sqlite"
    if jsonl_nonempty:
        return "jsonl"
    if sqlite_tables:
        return "sqlite"
    if jsonl_present:
        return "jsonl"
    raise ControlStateMigrationError(f"{data_dir} contains no legacy Analyzer scan control state")


ModelT = TypeVar("ModelT", bound=BaseModel)


def _latest_valid_records(
    records: Iterable[dict],
    model: type[ModelT],
    id_field: str,
    label: str,
) -> list[ModelT]:
    """Validate records and retain the last append for each stable id."""

    latest: dict[str, ModelT] = {}
    for record_number, raw in enumerate(records, start=1):
        try:
            parsed = model.model_validate(raw)
        except ValidationError as exc:
            raise ControlStateMigrationError(
                f"legacy {label} record {record_number} failed validation: {exc}"
            ) from exc
        record_id = str(getattr(parsed, id_field))
        # Reinsert so output order also follows the newest source occurrences.
        latest.pop(record_id, None)
        latest[record_id] = parsed
    return list(latest.values())


def _close_store(store: object) -> None:
    close = getattr(store, "close", None)
    if callable(close):
        close()


def _append_missing(
    store: _RecordStore,
    records: Iterable[BaseModel],
    id_field: str,
) -> tuple[int, int, set[str]]:
    migrated = 0
    skipped = 0
    migrated_ids: set[str] = set()
    for record in records:
        record_id = str(getattr(record, id_field))
        # Existing Form state wins. This makes retries safe after either a
        # complete run or a run interrupted halfway through.
        if store.find_one(id_field, record_id) is not None:
            skipped += 1
            continue
        store.append(record)
        migrated += 1
        migrated_ids.add(record_id)
    return migrated, skipped, migrated_ids


def migrate_control_state(
    analyzer_data_dir: Path,
    form_data_dir: Path,
    *,
    source_storage: SourceStorage = "auto",
    form_storage: FormStorage = "jsonl",
    migration_time: datetime | None = None,
) -> ControlStateMigrationResult:
    """Copy only legacy targets/jobs into an offline Form data directory.

    Source stores are opened read-only. Records are validated with Form's current
    control models and de-duplicated by their append order. Existing destination
    ids are never overwritten, so rerunning the command is idempotent.
    """

    source_dir = analyzer_data_dir.expanduser()
    destination_dir = form_data_dir.expanduser()
    if not source_dir.is_dir():
        raise ControlStateMigrationError(f"legacy Analyzer data directory not found: {source_dir}")
    if source_dir.resolve() == destination_dir.resolve():
        raise ControlStateMigrationError(
            "legacy Analyzer and Form data directories must be different"
        )
    if source_storage not in {"auto", "jsonl", "sqlite"}:
        raise ControlStateMigrationError(f"unknown source storage {source_storage!r}")
    if form_storage not in {"jsonl", "sqlite"}:
        raise ControlStateMigrationError(f"unknown Form storage {form_storage!r}")

    resolved_source = _resolve_source_storage(source_dir, source_storage)
    if resolved_source == "sqlite":
        sqlite_path = source_dir / _SQLITE_NAME
        available = _sqlite_control_tables(sqlite_path)
        target_rows = (
            _read_sqlite(sqlite_path, _SQLITE_TABLES["targets"])
            if _SQLITE_TABLES["targets"] in available
            else []
        )
        job_rows = (
            _read_sqlite(sqlite_path, _SQLITE_TABLES["jobs"])
            if _SQLITE_TABLES["jobs"] in available
            else []
        )
    else:
        target_rows = _read_jsonl(source_dir / _JSONL_FILES["targets"])
        job_rows = _read_jsonl(source_dir / _JSONL_FILES["jobs"])

    # Validate the complete source before creating or appending destination
    # stores. A corrupt source therefore cannot produce a partial first run.
    targets = _latest_valid_records(target_rows, ScanTarget, "target_id", "target")
    jobs = _latest_valid_records(job_rows, ScanJob, "job_id", "scan job")

    when = migration_time or datetime.now(UTC)
    when = when.replace(tzinfo=UTC) if when.tzinfo is None else when.astimezone(UTC)
    recovered_ids: set[str] = set()
    migrated_jobs: list[ScanJob] = []
    for job in jobs:
        if job.state in _IN_FLIGHT_STATES:
            job = ScanJob.model_validate(
                {
                    **job.model_dump(),
                    "state": ScanJobState.FAILED,
                    "finished_at": when,
                    "error": MIGRATED_IN_FLIGHT_ERROR,
                }
            )
            recovered_ids.add(job.job_id)
        migrated_jobs.append(job)

    target_store = create_form_store(destination_dir, "scan_targets", backend=form_storage)
    job_store = create_form_store(destination_dir, "scan_jobs", backend=form_storage)
    try:
        targets_migrated, targets_skipped, _ = _append_missing(target_store, targets, "target_id")
        jobs_migrated, jobs_skipped, migrated_job_ids = _append_missing(
            job_store, migrated_jobs, "job_id"
        )
    finally:
        _close_store(target_store)
        _close_store(job_store)

    return ControlStateMigrationResult(
        source_storage=resolved_source,
        target_rows_read=len(target_rows),
        unique_targets=len(targets),
        targets_migrated=targets_migrated,
        targets_skipped=targets_skipped,
        job_rows_read=len(job_rows),
        unique_jobs=len(jobs),
        jobs_migrated=jobs_migrated,
        jobs_skipped=jobs_skipped,
        in_flight_jobs_failed=len(recovered_ids & migrated_job_ids),
    )
