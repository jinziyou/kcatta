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

    def test_append_is_thread_safe(self, tmp_path):
        """Regression: a scan job appends from a worker thread (the runner uses
        asyncio.to_thread) while the long-lived write connection was opened on a
        different thread. Must not raise "SQLite objects created in a thread can
        only be used in that same thread" (the F1 connection-reuse bug)."""
        import threading

        store = SqliteStore(tmp_path / "analyzer.db", "alerts")
        store.append(_alert("main-thread"))  # opens the write connection here

        errors: list[Exception] = []

        def worker() -> None:
            try:
                store.append(_alert("worker-thread"))
            except Exception as exc:  # noqa: BLE001 - assert no error escapes
                errors.append(exc)

        t = threading.Thread(target=worker)
        t.start()
        t.join()

        assert not errors, f"cross-thread append raised: {errors}"
        assert {row["alert_id"] for row in store.tail(10)} == {"main-thread", "worker-thread"}

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


class TestJsonlScalability:
    def test_tail_reads_only_file_end_not_whole_file(self, tmp_path, monkeypatch):
        # F1: tail must read from the file end in bounded chunks, not slurp the
        # whole file. We track total bytes read and assert it stays far below the
        # full file size for a small tail limit.
        from analyzer.storage import jsonl as jsonl_mod

        store = JsonlStore(tmp_path / "alerts.jsonl")
        for i in range(2000):
            store.append(_alert(f"a-{i}"))
        total_size = (tmp_path / "alerts.jsonl").stat().st_size
        assert total_size > 256 * 1024  # ensure the file is meaningfully large

        bytes_read = {"n": 0}
        real_read = jsonl_mod.Path.open

        class _CountingFile:
            def __init__(self, fh):
                self._fh = fh

            def read(self, *a, **k):
                data = self._fh.read(*a, **k)
                bytes_read["n"] += len(data)
                return data

            def __getattr__(self, name):
                return getattr(self._fh, name)

            def __enter__(self):
                self._fh.__enter__()
                return self

            def __exit__(self, *exc):
                return self._fh.__exit__(*exc)

        def _wrapped_open(self, *args, **kwargs):
            handle = real_read(self, *args, **kwargs)
            mode = args[0] if args else kwargs.get("mode", "r")
            if "b" in mode:
                return _CountingFile(handle)
            return handle

        monkeypatch.setattr(jsonl_mod.Path, "open", _wrapped_open)
        tail = store.tail(5)
        assert [r["alert_id"] for r in tail] == [f"a-{i}" for i in range(1999, 1994, -1)]
        # Only the trailing region was read, not the whole 256KB+ file.
        assert bytes_read["n"] < total_size // 2, (bytes_read["n"], total_size)

    def test_tail_spanning_multiple_chunks(self, tmp_path):
        # A limit larger than what fits in one 64KiB block must still work.
        store = JsonlStore(tmp_path / "alerts.jsonl")
        for i in range(1000):
            store.append(_alert(f"a-{i}"))
        tail = store.tail(800)
        assert len(tail) == 800
        assert tail[0]["alert_id"] == "a-999"
        assert tail[-1]["alert_id"] == "a-200"

    def test_tail_handles_no_trailing_newline(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        store = JsonlStore(path)
        store.append(_alert("a-1"))
        # Append a final record WITHOUT a trailing newline.
        import json as _json

        with path.open("a", encoding="utf-8") as fh:
            fh.write(_json.dumps({"alert_id": "a-2", "severity": "high", "score": 1.0,
                                  "title": "t", "description": "d",
                                  "created_at": NOW.isoformat()}))
        ids = [r["alert_id"] for r in store.tail(10)]
        assert ids == ["a-2", "a-1"]

    def test_retention_caps_line_count(self, tmp_path):
        # With a line cap, the file rolls to keep only the newest records.
        store = JsonlStore(tmp_path / "alerts.jsonl", max_lines=100)
        for i in range(250):
            store.append(_alert(f"a-{i}"))
        tail = store.tail(1000)
        assert len(tail) <= 100
        assert tail[0]["alert_id"] == "a-249"  # newest retained
        # oldest records were trimmed
        assert all(r["alert_id"] != "a-0" for r in tail)


class TestSqliteScalability:
    def test_find_one_uses_index(self, tmp_path):
        import sqlite3

        SqliteStore(tmp_path / "analyzer.db", "scan_jobs")  # creates table + index
        with sqlite3.connect(tmp_path / "analyzer.db") as conn:
            plan = conn.execute(
                "EXPLAIN QUERY PLAN SELECT payload FROM scan_jobs "
                "WHERE json_extract(payload, '$.job_id') = ? LIMIT 1",
                ("x",),
            ).fetchall()
        detail = " ".join(str(r[-1]) for r in plan)
        assert "USING INDEX" in detail, detail

    def test_find_one_unknown_field_still_resolves(self, tmp_path):
        # A non-indexed field falls back to a scan but must still find the record
        # (parity with JsonlStore).
        store = SqliteStore(tmp_path / "analyzer.db", "alerts")
        store.append(_alert("a-1"))
        # 'title' is not indexed; should still match by scan.
        assert store.find_one("title", "test")["alert_id"] == "a-1"

    def test_find_one_rejects_bad_field_name(self, tmp_path):
        store = SqliteStore(tmp_path / "analyzer.db", "alerts")
        store.append(_alert("a-1"))
        # An injection-shaped field name is rejected, not interpolated into SQL.
        assert store.find_one("alert_id'); DROP TABLE alerts;--", "x") is None
        # the table is intact
        assert store.find_one("alert_id", "a-1")["alert_id"] == "a-1"

    def test_append_reuses_connection_fast(self, tmp_path):
        # Smoke: a burst of appends completes quickly (reused conn + WAL/NORMAL).
        import time

        store = SqliteStore(tmp_path / "analyzer.db", "alerts")
        start = time.time()
        for i in range(500):
            store.append(_alert(f"a-{i}"))
        assert time.time() - start < 10.0
        assert len(store.tail(1000)) == 500


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
