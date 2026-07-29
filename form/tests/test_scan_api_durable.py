"""HTTP contract for Form's durable scan queue controls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from analyzer.schemas import AssetReport
from analyzer.storage import StorageCapacityError
from fastapi.testclient import TestClient

from kcatta_form.analyzer_client import AnalyzerClient
from kcatta_form.api import create_app
from kcatta_form.schemas import ScanCapability, ScanJob, ScanJobState

CONTROL = {"Authorization": "Bearer admin-secret"}
INGEST = {"Authorization": "Bearer agent-secret"}
NOW = datetime(2026, 7, 13, tzinfo=UTC)


def _report() -> AssetReport:
    return AssetReport.model_validate(
        {
            "report_id": "report-api-1",
            "collected_at": NOW.isoformat(),
            "scanner_version": "test",
            "host": {"host_id": "host-1", "hostname": "node", "os": "Linux"},
            "assets": [],
            "vulnerabilities": [],
        }
    )


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/ingest/asset-report":
        return httpx.Response(202, json={"accepted": True, "id": "report-api-1"})
    if request.url.path == "/reports/asset-reports":
        return httpx.Response(200, json=[])
    return httpx.Response(200, json={"status": "ok"})


def _app(tmp_path: Path):  # type: ignore[no-untyped-def]
    analyzer = AnalyzerClient(
        "http://analyzer.internal:10068",
        "internal-secret",
        transport=httpx.MockTransport(_handler),
    )
    return create_app(
        data_dir=tmp_path,
        api_token="admin-secret",
        ingest_token="agent-secret",
        analyzer_client=analyzer,
    )


def _job(job_id: str, state: ScanJobState, **values) -> ScanJob:  # type: ignore[no-untyped-def]
    return ScanJob(
        job_id=job_id,
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.HOST,
        state=state,
        created_at=NOW,
        **values,
    )


def _register_target(client: TestClient) -> str:
    response = client.post(
        "/targets",
        headers=CONTROL,
        json={"name": "node", "address": "root@192.0.2.10", "transport": "ssh"},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["target_id"])


def test_trigger_idempotency_replays_same_job_and_conflicts_on_new_body(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", lambda target, options: _report())
    with TestClient(_app(tmp_path)) as client:
        target_id = _register_target(client)
        headers = {**CONTROL, "Idempotency-Key": "admin-invocation-1"}
        payload = {"target_id": target_id, "capability": "host", "options": {}}

        first = client.post("/scans", headers=headers, json=payload)
        replay = client.post("/scans", headers=headers, json=payload)
        conflict = client.post(
            "/scans",
            headers=headers,
            json={
                "target_id": target_id,
                "capability": "host",
                "options": {"scan_target": "host"},
            },
        )

    assert first.status_code == 202
    assert replay.status_code == 202
    assert replay.json()["job_id"] == first.json()["job_id"]
    assert conflict.status_code == 409
    assert "different scan request" in conflict.json()["detail"]


def test_blank_idempotency_key_is_rejected_as_client_error(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        target_id = _register_target(client)
        response = client.post(
            "/scans",
            headers={**CONTROL, "Idempotency-Key": "   "},
            json={"target_id": target_id, "capability": "host"},
        )

    assert response.status_code == 422
    assert "non-whitespace" in response.json()["detail"]


def test_queued_cancel_is_terminal_and_removes_spooled_artifact(tmp_path: Path) -> None:
    app = _app(tmp_path)
    # available_at must be in the real future so the lifespan worker cannot claim
    # the job before cancel; a fixed NOW (2026-07-13) is already in the past on
    # later dates and would turn RETRYING → RUNNING → CANCELLING instead.
    job = _job(
        "job-cancel-api",
        ScanJobState.RETRYING,
        attempt=1,
        available_at=datetime.now(UTC) + timedelta(days=1),
        error="temporary Analyzer outage",
    )
    app.state.scan_job_repository.create(job)
    app.state.scan_artifact_store.save(job.job_id, "asset-report", _report())

    with TestClient(app) as client:
        unauthorized = client.post(f"/scans/{job.job_id}/cancel", headers=INGEST)
        response = client.post(f"/scans/{job.job_id}/cancel", headers=CONTROL)

    assert unauthorized.status_code == 401
    assert response.status_code == 202
    assert response.json()["state"] == "cancelled"
    assert app.state.scan_artifact_store.load(job.job_id) is None


def test_failed_job_can_be_retried_and_invalid_retry_conflicts(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", lambda target, options: _report())
    app = _app(tmp_path)
    failed = _job(
        "job-retry-api",
        ScanJobState.FAILED,
        attempt=3,
        finished_at=NOW,
        error="permanent failure",
    )
    pending = _job(
        "job-pending-api",
        ScanJobState.PENDING,
        available_at=NOW + timedelta(days=1),
    )
    app.state.scan_job_repository.create(failed)
    app.state.scan_job_repository.create(pending)

    with TestClient(app) as client:
        retried = client.post(f"/scans/{failed.job_id}/retry", headers=CONTROL)
        conflict = client.post(f"/scans/{pending.job_id}/retry", headers=CONTROL)
        missing = client.post("/scans/missing/retry", headers=CONTROL)

    assert retried.status_code == 202
    assert retried.json()["state"] == "pending"
    assert retried.json()["attempt"] == 0
    assert conflict.status_code == 409
    assert missing.status_code == 404


def test_trigger_capacity_error_is_retryable_507(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    app = _app(tmp_path)
    with TestClient(app) as client:
        target_id = _register_target(client)

        def full(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise StorageCapacityError("scan-job database is full")

        monkeypatch.setattr(app.state.scan_job_repository, "create", full)
        response = client.post(
            "/scans",
            headers=CONTROL,
            json={"target_id": target_id, "capability": "host"},
        )

    assert response.status_code == 507
    assert response.headers["retry-after"] == "60"


def test_ready_degrades_when_durable_worker_is_unhealthy(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with TestClient(app) as client:
        app.state.scan_worker._last_loop_error = "sqlite unavailable"
        response = client.get("/ready", headers=CONTROL)

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["analyzer"] == "ready"
    assert body["worker"] == "unavailable"
    assert body["scheduler"] == "ready"
