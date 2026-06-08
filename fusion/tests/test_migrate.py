"""Tests for JSONL -> SQLite migration."""

from __future__ import annotations

from datetime import UTC, datetime

from fusion.schemas import Alert, Severity
from fusion.storage import JsonlStore, SqliteStore, migrate_jsonl_to_sqlite

NOW = datetime(2026, 5, 28, 10, 0, 0, tzinfo=UTC)


def _write_sample_jsonl(data_dir):
    alert = Alert(
        alert_id="a-1",
        severity=Severity.HIGH,
        score=75.0,
        title="test",
        description="demo",
        created_at=NOW,
    )
    JsonlStore(data_dir / "alerts.jsonl").append(alert)


def test_migrate_imports_jsonl_into_sqlite(tmp_path):
    _write_sample_jsonl(tmp_path)
    counts = migrate_jsonl_to_sqlite(tmp_path)
    assert counts["alerts"] == 1
    assert counts["asset_reports"] == 0

    store = SqliteStore(tmp_path / "fusion.db", "alerts")
    rows = store.tail(10)
    assert rows[0]["alert_id"] == "a-1"


def test_migrate_skips_when_sqlite_already_populated(tmp_path):
    _write_sample_jsonl(tmp_path)
    migrate_jsonl_to_sqlite(tmp_path)
    counts = migrate_jsonl_to_sqlite(tmp_path)
    assert counts["alerts"] == 0


def test_migrate_force_appends_duplicates(tmp_path):
    _write_sample_jsonl(tmp_path)
    migrate_jsonl_to_sqlite(tmp_path)
    counts = migrate_jsonl_to_sqlite(tmp_path, force=True)
    assert counts["alerts"] == 1
    store = SqliteStore(tmp_path / "fusion.db", "alerts")
    assert len(store.tail(10)) == 2
