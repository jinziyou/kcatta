"""Durable ingest ledger, restart replay, leases, and async derived work."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.api.ingest_queue import DerivedWorker, IngestLedger, LedgerConflictError
from analyzer.schemas import AssetReport

NOW = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)


def _asset_report(report_id: str = "r-durable") -> dict:
    return {
        "report_id": report_id,
        "collected_at": NOW.isoformat(),
        "scanner_version": "0.1.0",
        "host": {"host_id": "h-durable", "hostname": "node", "os": "Ubuntu 22.04"},
        "assets": [],
        "vulnerabilities": [],
    }


def _canonical_report(report_id: str = "r-durable") -> str:
    return AssetReport.model_validate(_asset_report(report_id)).model_dump_json()


def _wait_until(predicate, *, timeout: float = 3.0) -> None:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition was not satisfied before timeout")


def test_completed_outcome_survives_app_restart(tmp_path: Path) -> None:
    first_app = create_app(data_dir=tmp_path)
    with TestClient(first_app) as first_client:
        first = first_client.post("/ingest/asset-report", json=_asset_report())
        assert first.status_code == 202
        assert first.json()["derived_status"] == "partial"

    second_app = create_app(data_dir=tmp_path)
    with TestClient(second_app) as second_client:
        replay = second_client.post("/ingest/asset-report", json=_asset_report())
        assert replay.status_code == 202
        assert replay.json()["duplicate"] is True
        assert replay.json()["derived_status"] == first.json()["derived_status"]
        assert len(second_app.state.asset_report_store.tail(10)) == 1
        assert len(second_app.state.vulnerability_store.tail(10)) == 1


def test_only_one_ledger_instance_can_hold_a_live_lease(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    first = IngestLedger(path, max_completed=10)
    second = IngestLedger(path, max_completed=10)
    key = "asset-report:legacy:r-one-lease"
    first.submit(
        key=key,
        kind="asset-report",
        envelope_id="r-one-lease",
        payload=_canonical_report("r-one-lease"),
    )

    claimed = first.claim(key, lease_seconds=0.5)
    assert claimed is not None
    assert second.claim(key, lease_seconds=0.5) is None
    time.sleep(0.55)
    reclaimed = second.claim(key, lease_seconds=0.5)
    assert reclaimed is not None
    assert reclaimed.attempts == 2
    assert reclaimed.lease_token != claimed.lease_token


def test_pending_key_rejects_different_content(tmp_path: Path) -> None:
    ledger = IngestLedger(tmp_path / "ledger.db", max_completed=10)
    ledger.submit(
        key="asset-report:legacy:r-conflict",
        kind="asset-report",
        envelope_id="r-conflict",
        payload=_canonical_report("r-conflict"),
    )
    different = AssetReport.model_validate(
        {
            **_asset_report("r-conflict"),
            "host": {"host_id": "h-other", "hostname": "other", "os": "Ubuntu"},
        }
    ).model_dump_json()

    try:
        ledger.submit(
            key="asset-report:legacy:r-conflict",
            kind="asset-report",
            envelope_id="r-conflict",
            payload=different,
        )
    except LedgerConflictError:
        pass
    else:
        raise AssertionError("pending idempotency key accepted different content")


def test_api_returns_conflict_for_different_content_while_original_is_pending(
    tmp_path: Path,
) -> None:
    app = create_app(data_dir=tmp_path)
    app.state.ingest_ledger.submit(
        key="asset-report:legacy:r-api-conflict",
        kind="asset-report",
        envelope_id="r-api-conflict",
        payload=_canonical_report("r-api-conflict"),
    )
    different = {
        **_asset_report("r-api-conflict"),
        "host": {"host_id": "h-other", "hostname": "other", "os": "Ubuntu"},
    }

    with TestClient(app) as client:
        response = client.post("/ingest/asset-report", json=different)

    assert response.status_code == 409
    assert response.json() == {"detail": "envelope id was reused with different content"}


def test_worker_retries_then_commits_and_clears_payload(tmp_path: Path) -> None:
    ledger = IngestLedger(tmp_path / "ledger.db", max_completed=10)
    key = "asset-report:legacy:r-retry"
    ledger.submit(
        key=key,
        kind="asset-report",
        envelope_id="r-retry",
        payload=_canonical_report("r-retry"),
    )
    calls = 0

    def processor(_task):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("temporary derived store failure")
        return SimpleNamespace(
            status="complete",
            records=1,
            truncated=False,
            reason=None,
        )

    worker = DerivedWorker(
        ledger,
        processor,
        lease_seconds=0.2,
        poll_seconds=0.01,
        retry_base_seconds=0.01,
        retry_max_seconds=0.02,
    )
    worker.start()
    worker.notify()
    try:
        _wait_until(lambda: bool((task := ledger.get(key)) and task.final))
    finally:
        worker.stop()

    task = ledger.get(key)
    assert task is not None
    assert task.state == "complete"
    assert task.payload == ""
    assert task.attempts == 2


def test_completed_window_prunes_only_old_final_rows(tmp_path: Path) -> None:
    ledger = IngestLedger(tmp_path / "ledger.db", max_completed=2)
    ledger.submit(
        key="asset-report:legacy:r-still-pending",
        kind="asset-report",
        envelope_id="r-still-pending",
        payload=_canonical_report("r-still-pending"),
    )
    for index in range(3):
        key = f"asset-report:legacy:r-final-{index}"
        ledger.submit(
            key=key,
            kind="asset-report",
            envelope_id=f"r-final-{index}",
            payload=_canonical_report(f"r-final-{index}"),
        )
        task = ledger.claim(key, lease_seconds=1)
        assert task is not None and task.lease_token is not None
        assert ledger.complete(
            key,
            task.lease_token,
            status="complete",
            records=1,
            truncated=False,
            reason=None,
        )

    assert ledger.get("asset-report:legacy:r-final-0") is None
    assert ledger.get("asset-report:legacy:r-final-1") is not None
    assert ledger.get("asset-report:legacy:r-final-2") is not None
    assert ledger.get("asset-report:legacy:r-still-pending") is not None


def test_async_ingest_acknowledges_pending_then_worker_persists_results(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANALYZER_DERIVED_POLL_SECONDS", "0.01")
    monkeypatch.setenv("ANALYZER_DERIVED_RETRY_BASE_SECONDS", "0.01")
    monkeypatch.setenv("ANALYZER_DERIVED_RETRY_MAX_SECONDS", "0.05")
    app = create_app(data_dir=tmp_path, derived_async=True)

    with TestClient(app) as client:
        response = client.post("/ingest/asset-report", json=_asset_report("r-async"))
        assert response.status_code == 202
        assert response.json()["queued"] is True
        assert response.json()["derived_status"] == "pending"

        _wait_until(
            lambda: (
                len(app.state.asset_report_store.tail(10)) == 1
                and len(app.state.vulnerability_store.tail(10)) == 1
            )
        )
        replay = client.post("/ingest/asset-report", json=_asset_report("r-async"))
        assert replay.status_code == 202
        assert replay.json()["duplicate"] is True
        assert replay.json()["queued"] is False
        assert replay.json()["derived_status"] == "partial"
        ready = client.get("/ready").json()
        assert ready["derived_async"] is True
        assert ready["derived_queue"]["pending"] == 0


def test_status_endpoint_aggregates_logical_envelope_chunks(tmp_path: Path) -> None:
    app = create_app(data_dir=tmp_path, derived_async=False)
    ledger = app.state.ingest_ledger
    root = "r-lineage"
    base_key = f"asset-report:legacy:{root}"
    child_key = f"{base_key}::chunk-2-of-2"
    ledger.submit(
        key=base_key,
        kind="asset-report",
        envelope_id=root,
        payload=_canonical_report(root),
    )
    root_task = ledger.claim(base_key, lease_seconds=60)
    assert root_task is not None
    ledger.submit(
        key=child_key,
        kind="asset-report",
        envelope_id=f"{root}::chunk-2-of-2",
        payload=_canonical_report(f"{root}::chunk-2-of-2"),
    )
    child = ledger.claim(child_key, lease_seconds=60)
    assert child is not None and child.lease_token is not None
    assert ledger.complete(
        child_key,
        child.lease_token,
        status="partial",
        records=3,
        truncated=True,
        reason="max_records",
    )

    with TestClient(app) as client:
        response = client.get(
            "/ingest/status",
            params={"kind": "asset-report", "id": root, "source": "legacy"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "kind": "asset-report",
        "id": root,
        "source": "legacy",
        "state": "processing",
        "children": 2,
        "attempts": 2,
        "derived_records": 3,
        "derived_truncated": True,
        "derived_reason": "max_records",
        "last_error": None,
        "next_attempt_at": None,
        "updated_at": response.json()["updated_at"],
    }


def test_status_endpoint_returns_404_for_unknown_envelope(tmp_path: Path) -> None:
    app = create_app(data_dir=tmp_path, derived_async=False)
    with TestClient(app) as client:
        response = client.get(
            "/ingest/status",
            params={"kind": "trace-batch", "id": "missing"},
        )
    assert response.status_code == 404
