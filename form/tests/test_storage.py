"""Tests for persistence backends."""

from __future__ import annotations

from datetime import UTC, datetime

from form.schemas import Alert, Severity
from form.storage import JsonlStore, SqliteStore, create_store

NOW = datetime(2026, 5, 28, 10, 0, 0, tzinfo=UTC)


def _alert(alert_id: str) -> Alert:
    return Alert(
        alert_id=alert_id,
        severity=Severity.HIGH,
        score=75.0,
        title="test",
        description="test alert",
        created_at=NOW,
    )


class TestJsonlStore:
    def test_append_tail_and_find_one(self, tmp_path):
        store = JsonlStore(tmp_path / "alerts.jsonl")
        store.append(_alert("a-1"))
        store.append(_alert("a-2"))

        tail = store.tail(10)
        assert [row["alert_id"] for row in tail] == ["a-2", "a-1"]

        assert store.find_one("alert_id", "a-1")["alert_id"] == "a-1"
        assert store.find_one("alert_id", "missing") is None


class TestSqliteStore:
    def test_append_tail_and_find_one(self, tmp_path):
        store = SqliteStore(tmp_path / "form.db", "alerts")
        store.append(_alert("a-1"))
        store.append(_alert("a-2"))

        tail = store.tail(10)
        assert [row["alert_id"] for row in tail] == ["a-2", "a-1"]

        assert store.find_one("alert_id", "a-1")["alert_id"] == "a-1"
        assert store.find_one("alert_id", "missing") is None

    def test_shared_database_multiple_tables(self, tmp_path):
        db = tmp_path / "form.db"
        alerts = SqliteStore(db, "alerts")
        vulns = SqliteStore(db, "vulnerabilities")
        alerts.append(_alert("a-1"))
        vulns.append(_alert("v-1"))  # shape-compatible enough for storage test

        assert len(alerts.tail(10)) == 1
        assert len(vulns.tail(10)) == 1


class TestCreateStore:
    def test_factory_jsonl(self, tmp_path):
        store = create_store(tmp_path, "asset_reports", backend="jsonl")
        assert isinstance(store, JsonlStore)

    def test_factory_sqlite(self, tmp_path):
        store = create_store(tmp_path, "asset_reports", backend="sqlite")
        assert isinstance(store, SqliteStore)
