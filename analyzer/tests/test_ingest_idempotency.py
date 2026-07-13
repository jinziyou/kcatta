"""Idempotent ingest: a retried upload (same envelope id) must not double-store.

Agent uploads retry on transient failures; if the analyzer already processed a
request whose 202 the agent never saw, the retry would otherwise create a second
row. These tests assert the dedupe-by-id guard (CI1) collapses retries.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.api.idempotency import SeenIds
from analyzer.schemas import Vulnerability

NOW = datetime(2026, 5, 28, 10, 0, 0, tzinfo=UTC)


def _asset_report(report_id: str = "r-dup") -> dict:
    return {
        "report_id": report_id,
        "collected_at": NOW.isoformat(),
        "scanner_version": "0.1.0",
        "host": {"host_id": "h-1", "hostname": "n", "os": "Ubuntu 22.04"},
        "assets": [{"kind": "package", "asset_id": "pkg-1", "name": "openssl", "version": "3.0.2"}],
        "vulnerabilities": [],
    }


def _trace_batch(batch_id: str = "b-dup") -> dict:
    return {
        "batch_id": batch_id,
        "collected_at": NOW.isoformat(),
        "collector_id": "c-1",
        "collector_version": "0.1.0",
        "events": [],
    }


def _guard_batch(batch_id: str = "g-dup") -> dict:
    return {
        "batch_id": batch_id,
        "collected_at": NOW.isoformat(),
        "host_id": "h-1",
        "agent_version": "0.1.0",
        "events": [],
    }


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(data_dir=tmp_path)
    with TestClient(app) as test_client:
        yield test_client, app


def test_duplicate_asset_report_stored_once(client) -> None:
    c, app = client
    first = c.post("/ingest/asset-report", json=_asset_report())
    second = c.post("/ingest/asset-report", json=_asset_report())

    assert first.status_code == 202
    assert second.status_code == 202
    # Both acks carry the same id, but only one row is persisted.
    assert first.json()["id"] == second.json()["id"] == "r-dup"
    assert len(app.state.asset_report_store.tail(10)) == 1


def test_duplicate_trace_batch_stored_once(client) -> None:
    c, app = client
    assert c.post("/ingest/trace-batch", json=_trace_batch()).status_code == 202
    assert c.post("/ingest/trace-batch", json=_trace_batch()).status_code == 202
    assert len(app.state.trace_batch_store.tail(10)) == 1


def test_duplicate_guard_batch_stored_once(client) -> None:
    c, app = client
    assert c.post("/ingest/guard-event", json=_guard_batch()).status_code == 202
    assert c.post("/ingest/guard-event", json=_guard_batch()).status_code == 202
    assert len(app.state.guard_event_store.tail(10)) == 1


@pytest.mark.parametrize(
    ("route", "payload_factory", "main_store", "derived_store"),
    [
        ("/ingest/asset-report", _asset_report, "asset_report_store", "vulnerability_store"),
        ("/ingest/trace-batch", _trace_batch, "trace_batch_store", "alert_store"),
        ("/ingest/guard-event", _guard_batch, "guard_event_store", "alert_store"),
    ],
)
def test_derived_store_failure_keeps_durable_ack_and_dedupe_reservation(
    client, monkeypatch, route, payload_factory, main_store, derived_store
) -> None:
    c, app = client

    def fail_derived(_record) -> None:
        raise OSError("derived store unavailable")

    # Empty trace/guard payloads would not produce an alert, so force the
    # correlation/detection adapter to exercise the derived append path.
    if route == "/ingest/asset-report":
        monkeypatch.setattr(
            "analyzer.api.ingest.scanner_findings",
            lambda report: [
                Vulnerability(
                    vuln_id="scanner:test",
                    severity="high",
                    affected_asset_id="pkg-1",
                    source="kcatta-malware",
                )
            ],
        )
    elif route == "/ingest/trace-batch":
        monkeypatch.setattr("analyzer.api.ingest.correlate_trace_batch", lambda *_: [object()])
    else:
        monkeypatch.setattr("analyzer.api.ingest.correlate_guard_batch", lambda *_: [object()])
    monkeypatch.setattr(getattr(app.state, derived_store), "append", fail_derived)

    first = c.post(route, json=payload_factory())
    second = c.post(route, json=payload_factory())

    assert first.status_code == 202
    assert second.status_code == 202
    assert len(getattr(app.state, main_store).tail(10)) == 1


def test_distinct_ids_both_stored(client) -> None:
    c, app = client
    c.post("/ingest/asset-report", json=_asset_report("r-a"))
    c.post("/ingest/asset-report", json=_asset_report("r-b"))
    assert len(app.state.asset_report_store.tail(10)) == 2


def test_same_id_across_envelope_types_not_confused(client) -> None:
    # A trace batch and a guard batch that happen to share an id must each be
    # stored: the dedupe key is namespaced by envelope type.
    c, app = client
    c.post("/ingest/trace-batch", json=_trace_batch("shared-id"))
    c.post("/ingest/guard-event", json=_guard_batch("shared-id"))
    assert len(app.state.trace_batch_store.tail(10)) == 1
    assert len(app.state.guard_event_store.tail(10)) == 1


@pytest.mark.parametrize(
    ("route", "payload_factory", "store_name"),
    [
        ("/ingest/asset-report", _asset_report, "asset_report_store"),
        ("/ingest/trace-batch", _trace_batch, "trace_batch_store"),
        ("/ingest/guard-event", _guard_batch, "guard_event_store"),
    ],
)
def test_authenticated_agents_have_separate_envelope_id_namespaces(
    client, route, payload_factory, store_name
) -> None:
    c, app = client
    first = payload_factory("same-id")
    first["source_agent_id"] = "agent-a"
    second = payload_factory("same-id")
    second["source_agent_id"] = "agent-b"

    assert c.post(route, json=first).status_code == 202
    assert c.post(route, json=second).status_code == 202

    assert len(getattr(app.state, store_name).tail(10)) == 2


class TestSeenIds:
    def test_first_sight_then_duplicate(self) -> None:
        seen = SeenIds(maxlen=8)
        assert seen.check_and_add("x") is False
        assert seen.check_and_add("x") is True

    def test_fifo_eviction_drops_oldest(self) -> None:
        seen = SeenIds(maxlen=2)
        seen.check_and_add("a")
        seen.check_and_add("b")
        seen.check_and_add("c")  # evicts "a"
        assert len(seen) == 2
        # "a" was evicted, so it reads as fresh again ...
        assert seen.check_and_add("a") is False
        # ... while "c" is still remembered.
        assert seen.check_and_add("c") is True

    def test_duplicate_refreshes_recency(self) -> None:
        seen = SeenIds(maxlen=2)
        seen.check_and_add("a")
        seen.check_and_add("b")
        seen.check_and_add("a")  # touch "a" -> "b" becomes oldest
        seen.check_and_add("c")  # evicts "b", not "a"
        assert seen.check_and_add("a") is True
        assert seen.check_and_add("b") is False
