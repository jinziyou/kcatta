"""B7 + E2: scan-job lifecycle (startup recovery, timeout, concurrency cap)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app, scans
from analyzer.schemas import ScanCapability, ScanJob, ScanJobState, ScanTarget
from analyzer.storage import create_store

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def _job(job_id: str, state: ScanJobState) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        target_id="t-1",
        address="root@10.0.0.1",
        capability=ScanCapability.HOST,
        state=state,
        created_at=NOW,
    )


def _target() -> ScanTarget:
    return ScanTarget(target_id="t-1", name="t", address="root@10.0.0.1", created_at=NOW)


class _AppState:
    """Minimal app.state with a real scan_job_store for recovery tests."""

    def __init__(self, tmp_path: Path) -> None:
        self.scan_job_store = create_store(tmp_path, "scan_jobs", backend="jsonl")


# --- B7: startup recovery ---------------------------------------------------


def test_recover_stale_jobs_fails_in_flight_jobs(tmp_path: Path):
    state = _AppState(tmp_path)
    state.scan_job_store.append(_job("j-pending", ScanJobState.PENDING))
    state.scan_job_store.append(_job("j-running", ScanJobState.RUNNING))
    state.scan_job_store.append(_job("j-done", ScanJobState.SUCCEEDED))

    recovered = scans.recover_stale_jobs(state)
    assert recovered == 2

    latest = {r["job_id"]: r for r in scans._dedup_newest(state.scan_job_store.tail(100), "job_id")}
    assert latest["j-pending"]["state"] == "failed"
    assert "restarted" in latest["j-pending"]["error"]
    assert latest["j-running"]["state"] == "failed"
    assert latest["j-done"]["state"] == "succeeded"  # terminal jobs untouched


def test_lifespan_recovers_stale_jobs_on_startup(tmp_path: Path):
    # Seed a RUNNING job directly into the store, then start a fresh app: the
    # lifespan startup hook must flip it to FAILED.
    seed = create_store(tmp_path, "scan_jobs", backend="jsonl")
    seed.append(_job("j-orphan", ScanJobState.RUNNING))

    app = create_app(data_dir=tmp_path)
    with TestClient(app) as c:  # entering the context runs the lifespan startup
        job = c.get("/scans/j-orphan").json()
        assert job["state"] == "failed"
        assert "restarted" in job["error"]


# --- B7: per-job timeout ----------------------------------------------------


def test_run_job_times_out(tmp_path: Path, monkeypatch):
    state = _AppState(tmp_path)
    job = _job("j-slow", ScanJobState.PENDING)

    def _hang(target, options):
        import time

        time.sleep(5)  # would block far past the timeout

    monkeypatch.setattr("analyzer.deploy.trigger.run_host", _hang)

    asyncio.run(
        scans._run_job(
            state, job, _target(), "http://x", asyncio.Semaphore(1), timeout=0.05
        )
    )

    latest = scans._dedup_newest(state.scan_job_store.tail(100), "job_id")[0]
    assert latest["state"] == "failed"
    assert "timed out" in latest["error"]


# --- E2: concurrency cap ----------------------------------------------------


def test_run_job_respects_concurrency_semaphore(tmp_path: Path, monkeypatch):
    state = _AppState(tmp_path)
    sem = asyncio.Semaphore(2)
    live = 0
    peak = 0

    def _track(target, options):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        import time

        time.sleep(0.05)
        live -= 1
        from analyzer.schemas import AssetReport

        return AssetReport.model_validate(
            {
                "report_id": "r",
                "collected_at": NOW.isoformat(),
                "scanner_version": "0.1.0",
                "host": {"host_id": "h", "hostname": "n", "os": "Ubuntu 22.04"},
                "assets": [],
                "vulnerabilities": [],
            }
        )

    monkeypatch.setattr("analyzer.deploy.trigger.run_host", _track)
    monkeypatch.setattr("analyzer.api.scans.store_asset_report", lambda report, state: None)

    async def _drive():
        jobs = [_job(f"j-{i}", ScanJobState.PENDING) for i in range(6)]
        await asyncio.gather(
            *(scans._run_job(state, j, _target(), "http://x", sem, timeout=30) for j in jobs)
        )

    asyncio.run(_drive())
    # With a semaphore of 2, never more than 2 deploys run at the same instant.
    assert peak <= 2, f"concurrency cap violated: peak={peak}"


def test_max_concurrent_scans_env_override(monkeypatch):
    monkeypatch.setenv("ANALYZER_MAX_CONCURRENT_SCANS", "7")
    assert scans._max_concurrent_scans() == 7
    monkeypatch.setenv("ANALYZER_MAX_CONCURRENT_SCANS", "garbage")
    assert scans._max_concurrent_scans() == scans.DEFAULT_MAX_CONCURRENT_SCANS
    monkeypatch.setenv("ANALYZER_MAX_CONCURRENT_SCANS", "0")
    assert scans._max_concurrent_scans() == 1  # floored at 1


def test_scan_job_timeout_env_override(monkeypatch):
    monkeypatch.setenv("ANALYZER_SCAN_JOB_TIMEOUT_SECONDS", "12.5")
    assert scans._scan_job_timeout() == pytest.approx(12.5)
    monkeypatch.setenv("ANALYZER_SCAN_JOB_TIMEOUT_SECONDS", "nope")
    assert scans._scan_job_timeout() == float(scans.DEFAULT_SCAN_JOB_TIMEOUT_SECONDS)
