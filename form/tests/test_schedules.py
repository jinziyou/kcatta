"""Recurring scan schedules enqueue durable jobs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from kcatta_form.analyzer_client import AnalyzerClient
from kcatta_form.api import create_app
from kcatta_form.schedule_store import ScheduleStore
from kcatta_form.schedule_worker import ScheduleWorker

CONTROL = {"Authorization": "Bearer admin-secret"}


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/reports/asset-reports":
        return httpx.Response(200, json=[])
    if request.url.path == "/ready":
        return httpx.Response(
            200,
            json={
                "status": "ready",
                "osv": "ready",
                "osv_record_count": 1,
                "debian_tracker": "ready",
                "debian_tracker_record_count": 3,
                "debian_tracker_source_package_count": 1,
                "debian_tracker_synced_at": "2026-07-16T00:00:00+00:00",
                "debian_tracker_age_seconds": 60,
                "debian_tracker_max_age_seconds": 172800,
                "debian_tracker_auto_sync": True,
                "debian_tracker_refresh_seconds": 86400,
            },
        )
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


def test_schedule_api_crud_and_worker_enqueue(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with TestClient(app) as client:
        target = client.post(
            "/targets",
            headers=CONTROL,
            json={"name": "node", "address": "root@192.0.2.10", "transport": "ssh"},
        )
        assert target.status_code == 201, target.text
        target_id = target.json()["target_id"]

        created = client.post(
            "/schedules",
            headers=CONTROL,
            json={
                "target_id": target_id,
                "capability": "host",
                "interval_minutes": 60,
            },
        )
        assert created.status_code == 201, created.text
        schedule_id = created.json()["schedule_id"]

        listed = client.get("/schedules", headers=CONTROL)
        assert listed.status_code == 200
        assert len(listed.json()) == 1

        got = client.get(f"/schedules/{schedule_id}", headers=CONTROL)
        assert got.status_code == 200
        assert got.json()["capability"] == "host"

        # Force due and tick outside the background poller.
        store: ScheduleStore = app.state.schedule_store
        schedule = store.get(schedule_id)
        assert schedule is not None
        schedule.next_run_at = datetime.now(UTC) - timedelta(seconds=1)
        store._upsert(schedule)
        worker: ScheduleWorker = app.state.schedule_worker
        enqueued = worker.tick(datetime.now(UTC))
        assert enqueued == 1
        jobs = app.state.scan_job_repository.list(10)
        assert any(job.target_id == target_id for job in jobs)

        deleted = client.delete(f"/schedules/{schedule_id}", headers=CONTROL)
        assert deleted.status_code == 204
        assert client.get("/schedules", headers=CONTROL).json() == []


def test_ready_includes_scheduler_and_osv(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        response = client.get("/ready", headers=CONTROL)
    assert response.status_code == 200
    body = response.json()
    assert body["scheduler"] == "ready"
    assert body["osv"] == "ready"
    assert body["debian_tracker"] == "ready"
    assert body["debian_tracker_record_count"] == 3
    assert body["debian_tracker_age_seconds"] == 60
    assert body["debian_tracker_auto_sync"] is True


def test_ready_is_degraded_when_tracker_is_stale(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/reports/asset-reports":
            return httpx.Response(200, json=[])
        if request.url.path == "/ready":
            return httpx.Response(
                200,
                json={
                    "status": "degraded",
                    "osv": "ready",
                    "debian_tracker": "stale",
                    "debian_tracker_age_seconds": 200000,
                    "debian_tracker_max_age_seconds": 172800,
                },
            )
        return httpx.Response(200, json={"status": "ok"})

    analyzer = AnalyzerClient(
        "http://analyzer.internal:10068",
        "internal-secret",
        transport=httpx.MockTransport(handler),
    )
    app = create_app(
        data_dir=tmp_path,
        api_token="admin-secret",
        ingest_token="agent-secret",
        analyzer_client=analyzer,
    )

    with TestClient(app) as client:
        response = client.get("/ready", headers=CONTROL)

    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["debian_tracker"] == "stale"
