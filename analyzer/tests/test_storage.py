"""Tests for persistence backends."""

from __future__ import annotations

from datetime import UTC, datetime

from analyzer.schemas import Alert, Severity
from analyzer.storage import JsonlStore, SqliteStore, create_store

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

    def test_tail_tolerates_blank_and_truncated_lines(self, tmp_path):
        # Regression: a blank line or a crash-truncated half-record used to make
        # tail() raise JSONDecodeError, 500-ing every /reports list endpoint.
        path = tmp_path / "alerts.jsonl"
        store = JsonlStore(path)
        store.append(_alert("a-1"))
        store.append(_alert("a-2"))
        # Inject a blank line in the middle and a truncated final record (no newline).
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\n")
            fh.write('{"alert_id": "a-3", "sev')  # truncated, no newline

        tail = store.tail(10)
        ids = [row["alert_id"] for row in tail]
        assert "a-1" in ids and "a-2" in ids  # valid records survive
        assert "a-3" not in ids  # truncated record skipped, not fatal
        # find_one stays usable on the same corrupted file.
        assert store.find_one("alert_id", "a-1")["alert_id"] == "a-1"


class TestSqliteStore:
    def test_append_tail_and_find_one(self, tmp_path):
        store = SqliteStore(tmp_path / "analyzer.db", "alerts")
        store.append(_alert("a-1"))
        store.append(_alert("a-2"))

        tail = store.tail(10)
        assert [row["alert_id"] for row in tail] == ["a-2", "a-1"]

        assert store.find_one("alert_id", "a-1")["alert_id"] == "a-1"
        assert store.find_one("alert_id", "missing") is None

    def test_shared_database_multiple_tables(self, tmp_path):
        db = tmp_path / "analyzer.db"
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


def test_find_one_scans_beyond_500_both_backends(tmp_path):
    """Regression: find_one must locate a record older than the newest 500 on BOTH
    backends. JSONL previously capped its scan at 500, diverging from SQLite (which
    scans the whole table) — so the same id 404'd on JSONL but resolved on SQLite."""
    jsonl = JsonlStore(tmp_path / "alerts.jsonl")
    sqlite = SqliteStore(tmp_path / "analyzer.db", "alerts")
    for i in range(600):
        a = _alert(f"a-{i}")
        jsonl.append(a)
        sqlite.append(a)
    # a-0 is the OLDEST of 600 — beyond the old 500-record JSONL window
    assert jsonl.find_one("alert_id", "a-0")["alert_id"] == "a-0"
    assert sqlite.find_one("alert_id", "a-0")["alert_id"] == "a-0"
