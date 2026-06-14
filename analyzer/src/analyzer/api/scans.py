"""Target registry + scan trigger/job API.

The admin calls these to register targets and trigger remote scans. A trigger
creates a `ScanJob` (pending), schedules an async background runner that deploys
the agent via `analyzer.deploy.trigger` (off the event loop with
``asyncio.to_thread``), ingests the produced artifact through the same path as an
agent upload, records the result on the job, and flips it to succeeded/failed.

Jobs and targets are persisted append-only: each state transition appends a new
row with the same id; reads take the newest (`find_one`) and lists de-duplicate
by id (`tail` is newest-first).
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from starlette.datastructures import State

from ..deploy import bootstrap
from ..deploy import trigger as deploy_trigger
from ..schemas import (
    CredentialMode,
    ScanCapability,
    ScanJob,
    ScanJobState,
    ScanResult,
    ScanTarget,
    ScanTargetInput,
    Transport,
    TriggerScanRequest,
)
from .ingest import store_asset_report, store_trace_batch

router = APIRouter(tags=["scans"])


def _now() -> datetime:
    return datetime.now(UTC)


def _public_url() -> str:
    """analyzer URL the guard daemon on a target should push events to."""
    return os.getenv("ANALYZER_PUBLIC_URL", "http://127.0.0.1:8000")


def _dedup_newest(records: list[dict], key: str) -> list[dict]:
    """Keep the first occurrence of each ``key`` (``tail`` is newest-first)."""
    seen: set[str] = set()
    out: list[dict] = []
    for record in records:
        value = record.get(key)
        if value in seen:
            continue
        seen.add(value)
        out.append(record)
    return out


# --------------------------------------------------------------- targets


@router.post("/targets", status_code=status.HTTP_201_CREATED, response_model=ScanTarget)
async def register_target(payload: ScanTargetInput, request: Request) -> ScanTarget:
    """Register a scan target. A one-time `password` (managed_key mode, SSH) bootstraps
    a managed key on the analyzer host and is then discarded — never persisted."""
    if payload.credential_mode == CredentialMode.MANAGED_KEY and payload.password:
        if payload.transport != Transport.SSH:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="managed-key bootstrap is SSH-only",
            )
        try:
            await asyncio.to_thread(
                bootstrap.ensure_key_auth, payload.address, payload.port, None, payload.password
            )
        except Exception as exc:  # noqa: BLE001 - surface bootstrap failure to the caller
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"managed-key bootstrap failed: {exc}",
            ) from exc

    target = ScanTarget(
        target_id=f"target-{uuid.uuid4()}",
        name=payload.name,
        address=payload.address,
        port=payload.port,
        transport=payload.transport,
        credential_mode=payload.credential_mode,
        identity_path=payload.identity_path,
        created_at=_now(),
    )
    request.app.state.scan_target_store.append(target)
    return target


@router.get("/targets", response_model=list[ScanTarget])
async def list_targets(request: Request) -> list[dict]:
    """List registered targets, newest registration per target_id first."""
    return _dedup_newest(request.app.state.scan_target_store.tail(500), "target_id")


@router.get("/targets/{target_id}", response_model=ScanTarget)
async def get_target(target_id: str, request: Request) -> dict:
    """Fetch a single registered target by id."""
    record = request.app.state.scan_target_store.find_one("target_id", target_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    return record


# ----------------------------------------------------------------- scans


@router.post("/scans", status_code=status.HTTP_202_ACCEPTED, response_model=ScanJob)
async def trigger_scan(
    payload: TriggerScanRequest, request: Request, background: BackgroundTasks
) -> ScanJob:
    """Trigger a scan against a registered target; runs asynchronously."""
    target_record = request.app.state.scan_target_store.find_one("target_id", payload.target_id)
    if target_record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    target = ScanTarget.model_validate(target_record)

    job = ScanJob(
        job_id=f"scan-{uuid.uuid4()}",
        target_id=target.target_id,
        address=target.address,
        capability=payload.capability,
        state=ScanJobState.PENDING,
        options=payload.options,
        created_at=_now(),
    )
    request.app.state.scan_job_store.append(job)
    background.add_task(_run_job, request.app.state, job, target, _public_url())
    return job


@router.get("/scans", response_model=list[ScanJob])
async def list_scans(request: Request) -> list[dict]:
    """List scan jobs, newest state per job_id first."""
    return _dedup_newest(request.app.state.scan_job_store.tail(1000), "job_id")


@router.get("/scans/{job_id}", response_model=ScanJob)
async def get_scan(job_id: str, request: Request) -> dict:
    """Fetch a scan job (its latest state) by id."""
    record = request.app.state.scan_job_store.find_one("job_id", job_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan job not found")
    return record


async def _run_job(state: State, job: ScanJob, target: ScanTarget, public_url: str) -> None:
    """Background runner: deploy → ingest → record result. Never raises."""
    job.state = ScanJobState.RUNNING
    job.started_at = _now()
    state.scan_job_store.append(job)

    try:
        if job.capability == ScanCapability.HOST:
            report = await asyncio.to_thread(deploy_trigger.run_host, target, job.options)
            await asyncio.to_thread(store_asset_report, report, state)
            job.result = ScanResult(
                kind=ScanCapability.HOST, report_id=report.report_id, host_id=report.host.host_id
            )
        elif job.capability == ScanCapability.TRACE:
            batch = await asyncio.to_thread(deploy_trigger.run_trace, target, job.options)
            await asyncio.to_thread(store_trace_batch, batch, state)
            job.result = ScanResult(kind=ScanCapability.TRACE, batch_id=batch.batch_id)
        else:  # guard: starts a persistent daemon that uploads its own events
            job.result = await asyncio.to_thread(deploy_trigger.run_guard, target, public_url)
        job.state = ScanJobState.SUCCEEDED
    except Exception as exc:  # noqa: BLE001 - any failure is recorded on the job, not raised
        job.state = ScanJobState.FAILED
        job.error = str(exc)
    finally:
        job.finished_at = _now()
        state.scan_job_store.append(job)
