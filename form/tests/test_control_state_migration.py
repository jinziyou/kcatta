"""Legacy Analyzer target/job migration into Form-owned persistence."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from analyzer.storage import create_store
from pydantic import BaseModel

from kcatta_form.cli import migrate_control_state_main
from kcatta_form.control_state_migration import (
    MIGRATED_IN_FLIGHT_ERROR,
    ControlStateMigrationError,
    migrate_control_state,
)
from kcatta_form.schemas import ScanCapability, ScanJob, ScanJobState, ScanTarget
from kcatta_form.storage import create_form_store, latest_legacy_scan_jobs

NOW = datetime(2026, 7, 10, 9, 0, tzinfo=UTC)
LATER = datetime(2026, 7, 10, 10, 0, tzinfo=UTC)


def _target(target_id: str, name: str) -> ScanTarget:
    return ScanTarget(
        target_id=target_id,
        name=name,
        address=f"root@{target_id}.example",
        created_at=NOW,
    )


def _job(job_id: str, state: ScanJobState) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        target_id="target-1",
        address="root@target-1.example",
        capability=ScanCapability.HOST,
        state=state,
        created_at=NOW,
        started_at=NOW if state != ScanJobState.PENDING else None,
        finished_at=LATER if state in {ScanJobState.SUCCEEDED, ScanJobState.FAILED} else None,
    )


def _write_jsonl(path: Path, records: list[BaseModel | dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        record.model_dump_json() if isinstance(record, BaseModel) else json.dumps(record)
        for record in records
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _close(store: object) -> None:
    close = getattr(store, "close", None)
    if callable(close):
        close()


def test_jsonl_migration_deduplicates_recovers_and_is_idempotent(tmp_path: Path) -> None:
    old = tmp_path / "old-analyzer"
    destination = tmp_path / "form"
    target_rows = [
        _target("target-1", "old name"),
        _target("target-existing", "legacy must not overwrite Form"),
        _target("target-1", "newest name"),
    ]
    job_rows = [
        _job("job-running", ScanJobState.PENDING),
        _job("job-pending", ScanJobState.PENDING),
        _job("job-done", ScanJobState.PENDING),
        _job("job-running", ScanJobState.RUNNING),
        _job("job-done", ScanJobState.SUCCEEDED),
    ]
    _write_jsonl(old / "scan-targets.jsonl", target_rows)
    _write_jsonl(old / "scan-jobs.jsonl", job_rows)
    # This must neither be parsed nor appear in the Form destination.
    (old / "asset-reports.jsonl").write_text("not even valid telemetry\n", encoding="utf-8")
    source_before = (old / "scan-jobs.jsonl").read_bytes()

    target_store = create_store(destination, "scan_targets", backend="jsonl")
    target_store.append(_target("target-existing", "Form-owned name"))

    result = migrate_control_state(
        old,
        destination,
        source_storage="auto",
        form_storage="jsonl",
        migration_time=LATER,
    )

    assert result.source_storage == "jsonl"
    assert (result.target_rows_read, result.unique_targets) == (3, 2)
    assert (result.targets_migrated, result.targets_skipped) == (1, 1)
    assert (result.job_rows_read, result.unique_jobs) == (5, 3)
    assert (result.jobs_migrated, result.jobs_skipped) == (3, 0)
    assert result.in_flight_jobs_failed == 2

    targets = create_store(destination, "scan_targets", backend="jsonl")
    jobs = create_store(destination, "scan_jobs", backend="jsonl")
    assert targets.find_one("target_id", "target-1")["name"] == "newest name"
    assert targets.find_one("target_id", "target-existing")["name"] == "Form-owned name"
    for job_id in ("job-pending", "job-running"):
        migrated = jobs.find_one("job_id", job_id)
        assert migrated["state"] == "failed"
        assert migrated["finished_at"] == LATER.isoformat().replace("+00:00", "Z")
        assert migrated["error"] == MIGRATED_IN_FLIGHT_ERROR
    assert jobs.find_one("job_id", "job-done")["state"] == "succeeded"
    assert not (destination / "asset-reports.jsonl").exists()
    assert (old / "scan-jobs.jsonl").read_bytes() == source_before

    target_lines = (destination / "scan-targets.jsonl").read_bytes()
    job_lines = (destination / "scan-jobs.jsonl").read_bytes()
    rerun = migrate_control_state(
        old,
        destination,
        source_storage="jsonl",
        form_storage="jsonl",
        migration_time=datetime(2030, 1, 1, tzinfo=UTC),
    )
    assert (rerun.targets_migrated, rerun.jobs_migrated) == (0, 0)
    assert (rerun.targets_skipped, rerun.jobs_skipped) == (2, 3)
    assert rerun.in_flight_jobs_failed == 0
    assert (destination / "scan-targets.jsonl").read_bytes() == target_lines
    assert (destination / "scan-jobs.jsonl").read_bytes() == job_lines


def test_sqlite_migration_auto_prefers_populated_database_and_excludes_telemetry(
    tmp_path: Path,
) -> None:
    old = tmp_path / "old-analyzer"
    destination = tmp_path / "form"
    targets = create_store(old, "scan_targets", backend="sqlite")
    jobs = create_store(old, "scan_jobs", backend="sqlite")
    targets.append(_target("target-1", "sqlite old"))
    targets.append(_target("target-1", "sqlite newest"))
    jobs.append(_job("job-running", ScanJobState.RUNNING))
    _close(targets)
    _close(jobs)

    with sqlite3.connect(old / "analyzer.db") as connection:
        connection.execute(
            "CREATE TABLE asset_reports "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO asset_reports(payload) VALUES (?)", ('{"sentinel": true}',))
        connection.commit()
    # A stale JSONL file may remain after Analyzer's old JSONL -> SQLite migration.
    _write_jsonl(old / "scan-targets.jsonl", [_target("target-jsonl", "stale")])

    result = migrate_control_state(
        old,
        destination,
        source_storage="auto",
        form_storage="sqlite",
        migration_time=LATER,
    )

    assert result.source_storage == "sqlite"
    assert (result.target_rows_read, result.unique_targets) == (2, 1)
    assert result.in_flight_jobs_failed == 1
    migrated_targets = create_form_store(destination, "scan_targets", backend="sqlite")
    migrated_jobs = create_form_store(destination, "scan_jobs", backend="sqlite")
    assert migrated_targets.find_one("target_id", "target-1")["name"] == "sqlite newest"
    assert migrated_targets.find_one("target_id", "target-jsonl") is None
    assert migrated_jobs.find_one("job_id", "job-running")["state"] == "failed"
    _close(migrated_targets)
    _close(migrated_jobs)

    with sqlite3.connect(destination / "form.db") as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert "asset_reports" not in tables
    assert {"scan_targets", "scan_jobs"} <= tables


def test_corrupt_source_fails_before_creating_destination(tmp_path: Path) -> None:
    old = tmp_path / "old-analyzer"
    destination = tmp_path / "form"
    old.mkdir()
    (old / "scan-targets.jsonl").write_text('{"target_id":\n', encoding="utf-8")

    with pytest.raises(ControlStateMigrationError, match="invalid JSON"):
        migrate_control_state(old, destination, source_storage="jsonl")

    assert not destination.exists()


def test_source_and_destination_must_differ(tmp_path: Path) -> None:
    old = tmp_path / "data"
    old.mkdir()
    (old / "scan-targets.jsonl").touch()

    with pytest.raises(ControlStateMigrationError, match="must be different"):
        migrate_control_state(old, old)


def test_cli_reports_counts_and_scope(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    old = tmp_path / "old-analyzer"
    destination = tmp_path / "form"
    _write_jsonl(old / "scan-targets.jsonl", [_target("target-1", "one")])
    (old / "scan-jobs.jsonl").touch()

    migrate_control_state_main(
        [
            "--analyzer-data-dir",
            str(old),
            "--form-data-dir",
            str(destination),
            "--source-storage",
            "jsonl",
            "--form-storage",
            "jsonl",
        ]
    )

    output = capsys.readouterr().out
    assert "source=jsonl targets=1/1 jobs=0/0" in output
    assert "Analyzer telemetry, credentials, tokens" in output


def test_jsonl_legacy_loader_reads_all_rows_and_keeps_latest_per_job(tmp_path: Path) -> None:
    data_dir = tmp_path / "form"
    path = data_dir / "scan-jobs.jsonl"
    path.parent.mkdir(parents=True)
    rows = [{"job_id": "old-pending", "state": "pending"}]
    rows.extend({"job_id": f"new-{index}", "state": "succeeded"} for index in range(1_005))
    rows.append({"job_id": "new-0", "state": "failed"})
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n{malformed\n",
        encoding="utf-8",
    )
    store = create_form_store(data_dir, "scan_jobs", backend="jsonl")

    loaded = latest_legacy_scan_jobs(store)

    indexed = {row["job_id"]: row for row in loaded}
    assert indexed["old-pending"]["state"] == "pending"
    assert indexed["new-0"]["state"] == "failed"
    assert len(indexed) == 1_006


def test_sqlite_legacy_loader_reads_all_rows_and_keeps_latest_per_job(tmp_path: Path) -> None:
    data_dir = tmp_path / "form"
    store = create_form_store(data_dir, "scan_jobs", backend="sqlite")
    table = store.table
    _close(store)
    rows = [
        (json.dumps({"job_id": "old-pending", "state": "pending"}),),
        (json.dumps({"job_id": "other", "state": "succeeded"}),),
        (json.dumps({"job_id": "other", "state": "failed"}),),
    ]
    with sqlite3.connect(data_dir / "form.db") as connection:
        connection.executemany(f"INSERT INTO {table}(payload) VALUES (?)", rows)
        connection.commit()
    reopened = create_form_store(data_dir, "scan_jobs", backend="sqlite")

    loaded = latest_legacy_scan_jobs(reopened)

    indexed = {row["job_id"]: row for row in loaded}
    assert indexed == {
        "old-pending": {"job_id": "old-pending", "state": "pending"},
        "other": {"job_id": "other", "state": "failed"},
    }
    _close(reopened)
