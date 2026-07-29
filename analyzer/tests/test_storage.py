"""Tests for persistence backends."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from analyzer.schemas import Alert, AssetReport, Severity
from analyzer.storage import JsonlStore, SqliteStore, StorageCapacityError, create_store

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


def _asset_report(report_id: str) -> AssetReport:
    return AssetReport.model_validate(
        {
            "report_id": report_id,
            "collected_at": NOW,
            "scanner_version": "test",
            "host": {"host_id": "h-1", "hostname": "n", "os": "Debian 12"},
        }
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

    def test_find_lineage_uses_one_pass_and_exact_chunk_parsing(self, tmp_path):
        store = JsonlStore(tmp_path / "asset-reports.jsonl", fsync=False)
        ids = (
            "logical-r::chunk-1-of-2",
            "logical-r::chunk-2-of-2",
            "logical-r~report-part-0",
        )
        for report_id in ("unrelated", *ids, "logical-r::chunk-x-of-2"):
            store.append(_asset_report(report_id))

        rows = store.find_lineage("report_id", ids[1], "asset")

        assert {row["report_id"] for row in rows} == set(ids)

    def test_lineage_fingerprint_ignores_unrelated_appends(self, tmp_path):
        store = JsonlStore(tmp_path / "asset-reports.jsonl", fsync=False)
        store.append(_asset_report("logical-r::chunk-1-of-2"))
        store.append(_asset_report("logical-r::chunk-2-of-2"))
        original = store.lineage_fingerprint("report_id", "logical-r", "asset")

        store.append(_asset_report("unrelated"))
        assert store.lineage_fingerprint("report_id", "logical-r", "asset") == original

        store.append(_asset_report("logical-r::chunk-1-of-2"))
        assert store.lineage_fingerprint("report_id", "logical-r", "asset") != original


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

    def test_find_lineage_returns_only_the_requested_logical_upload(self, tmp_path):
        store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
        ids = ("logical-r::chunk-1-of-2", "logical-r::chunk-2-of-2")
        for report_id in (ids[0], "unrelated", ids[1]):
            store.append(_asset_report(report_id))

        rows = store.find_lineage("report_id", ids[1], "asset")

        assert {row["report_id"] for row in rows} == set(ids)

    def test_lineage_fingerprint_ignores_unrelated_appends(self, tmp_path):
        store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
        store.append(_asset_report("logical-r::chunk-1-of-2"))
        store.append(_asset_report("logical-r::chunk-2-of-2"))
        original = store.lineage_fingerprint("report_id", "logical-r", "asset")

        store.append(_asset_report("unrelated"))
        assert store.lineage_fingerprint("report_id", "logical-r", "asset") == original

        store.append(_asset_report("logical-r::chunk-1-of-2"))
        assert store.lineage_fingerprint("report_id", "logical-r", "asset") != original

    def test_lineage_index_covers_rows_from_an_existing_database(self, tmp_path):
        import sqlite3

        database = tmp_path / "analyzer.db"
        with sqlite3.connect(database) as conn:
            conn.execute(
                "CREATE TABLE asset_reports ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT INTO asset_reports (payload) VALUES (?)",
                (_asset_report("legacy-r::chunk-1-of-2").model_dump_json(),),
            )
            conn.commit()

        store = SqliteStore(database, "asset_reports")

        rows = store.find_lineage("report_id", "legacy-r", "asset")
        assert [row["report_id"] for row in rows] == ["legacy-r::chunk-1-of-2"]


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

    def test_offset_page_can_reach_beyond_return_byte_budget(self, tmp_path):
        # The read budget caps returned JSON, not how far the pager may seek;
        # otherwise older retained history becomes unreachable.
        store = JsonlStore(tmp_path / "alerts.jsonl", read_max_bytes=1_000)
        for i in range(100):
            store.append(_alert(f"a-{i}"))

        page = store.tail(2, offset=98)

        assert [row["alert_id"] for row in page] == ["a-1", "a-0"]

    def test_tail_handles_no_trailing_newline(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        store = JsonlStore(path)
        store.append(_alert("a-1"))
        # Append a final record WITHOUT a trailing newline.
        import json as _json

        with path.open("a", encoding="utf-8") as fh:
            fh.write(
                _json.dumps(
                    {
                        "alert_id": "a-2",
                        "severity": "high",
                        "score": 1.0,
                        "title": "t",
                        "description": "d",
                        "created_at": NOW.isoformat(),
                    }
                )
            )
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

    def test_byte_retention_is_strict_and_keeps_newest_complete_records(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        store = JsonlStore(path, max_bytes=2_000, max_record_bytes=2_000, fsync=False)
        for i in range(40):
            store.append(_alert(f"byte-{i}"))

        assert path.stat().st_size <= 2_000
        ids = [row["alert_id"] for row in store.tail(100)]
        assert ids[0] == "byte-39"
        assert "byte-0" not in ids

    def test_record_larger_than_budget_is_rejected_before_write(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        store = JsonlStore(path, max_bytes=10_000, max_record_bytes=64, fsync=False)
        with pytest.raises(StorageCapacityError):
            store.append(_alert("too-large"))
        assert not path.exists()

    def test_tail_has_a_total_read_byte_budget(self, tmp_path):
        store = JsonlStore(
            tmp_path / "alerts.jsonl",
            max_bytes=100_000,
            read_max_bytes=1_000,
            fsync=False,
        )
        for i in range(30):
            store.append(_alert(f"read-{i}"))
        rows = store.tail(1_000)
        assert rows
        assert rows[0]["alert_id"] == "read-29"
        assert len(rows) < 30


class TestSqliteScalability:
    def test_find_one_uses_index(self, tmp_path):
        import sqlite3

        SqliteStore(tmp_path / "analyzer.db", "scan_jobs")  # shared Form store + index
        with sqlite3.connect(tmp_path / "analyzer.db") as conn:
            plan = conn.execute(
                "EXPLAIN QUERY PLAN SELECT payload FROM scan_jobs "
                "WHERE json_extract(payload, '$.job_id') = ? LIMIT 1",
                ("x",),
            ).fetchall()
        detail = " ".join(str(r[-1]) for r in plan)
        assert "USING INDEX" in detail, detail

    def test_find_lineage_uses_persistent_expression_index(self, tmp_path):
        store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
        store.append(_asset_report("logical-r::chunk-1-of-2"))
        with store._connect() as conn:
            plan = conn.execute(
                "EXPLAIN QUERY PLAN SELECT payload FROM asset_reports "
                "WHERE kcatta_lineage_key_v1("
                "json_extract(payload, '$.report_id'), 'asset') = ?",
                ("logical-r",),
            ).fetchall()
        detail = " ".join(str(row[-1]) for row in plan)
        assert "idx_asset_reports_report_id_lineage_v1" in detail, detail

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

    def test_row_and_logical_byte_retention_delete_oldest(self, tmp_path):
        store = SqliteStore(
            tmp_path / "analyzer.db",
            "alerts",
            max_rows=3,
            max_table_bytes=2_000,
            max_record_bytes=2_000,
        )
        for i in range(10):
            store.append(_alert(f"bounded-{i}"))
        ids = [row["alert_id"] for row in store.tail(100)]
        assert ids == ["bounded-9", "bounded-8", "bounded-7"]

    def test_record_larger_than_sqlite_record_budget_is_rejected(self, tmp_path):
        store = SqliteStore(
            tmp_path / "analyzer.db",
            "alerts",
            max_record_bytes=64,
        )
        with pytest.raises(StorageCapacityError):
            store.append(_alert("too-large"))
        assert store.tail(10) == []

    def test_stores_for_one_database_share_the_quota_writer_lock(self, tmp_path):
        database = tmp_path / "analyzer.db"
        alerts = SqliteStore(database, "alerts")
        vulnerabilities = SqliteStore(database, "vulnerabilities")
        assert alerts._write_lock is vulnerabilities._write_lock


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
