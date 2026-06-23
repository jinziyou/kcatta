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
import logging
import os
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from starlette.datastructures import State

from ..deploy import bootstrap, winrm_bootstrap
from ..deploy import trigger as deploy_trigger
from ..deploy._util import split_user_host
from ..schemas import (
    CredentialMode,
    GuardLifecycleStatus,
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

logger = logging.getLogger("analyzer.api.scans")

router = APIRouter(tags=["scans"])

# E2: cap concurrent in-process scan jobs so a batch trigger can't saturate the
# thread pool / overwhelm the box. Configurable; sensible default of 4.
DEFAULT_MAX_CONCURRENT_SCANS = 4
# B7: a job that hangs (dead SSH, unresponsive target) must not stay RUNNING
# forever — bound each run. Default 30 minutes; override via env.
DEFAULT_SCAN_JOB_TIMEOUT_SECONDS = 30 * 60


def _max_concurrent_scans() -> int:
    raw = os.getenv("ANALYZER_MAX_CONCURRENT_SCANS")
    try:
        value = int(raw) if raw else DEFAULT_MAX_CONCURRENT_SCANS
    except ValueError:
        value = DEFAULT_MAX_CONCURRENT_SCANS
    return max(1, value)


def _scan_job_timeout() -> float:
    raw = os.getenv("ANALYZER_SCAN_JOB_TIMEOUT_SECONDS")
    try:
        value = float(raw) if raw else float(DEFAULT_SCAN_JOB_TIMEOUT_SECONDS)
    except ValueError:
        value = float(DEFAULT_SCAN_JOB_TIMEOUT_SECONDS)
    return max(1.0, value)


def _now() -> datetime:
    return datetime.now(UTC)


def _public_url() -> str:
    """analyzer URL the guard daemon on a target should push events to."""
    return os.getenv("ANALYZER_PUBLIC_URL", "http://127.0.0.1:10068")


def recover_stale_jobs(state: State) -> int:
    """Fail jobs left mid-flight by a previous process (B7 recovery).

    BackgroundTasks run inside the uvicorn process; a restart/crash while a job
    is PENDING/RUNNING orphans it forever (no runner left to flip it). On
    startup, transition every still-pending/running job to FAILED so the admin
    sees a terminal state instead of a permanent RUNNING. Returns the count.
    """
    jobs = _dedup_newest(state.scan_job_store.tail(1000), "job_id")
    recovered = 0
    for record in jobs:
        if record.get("state") in (ScanJobState.PENDING.value, ScanJobState.RUNNING.value):
            try:
                job = ScanJob.model_validate(record)
            except Exception:  # noqa: BLE001 - a corrupt row must not block startup
                continue
            job.state = ScanJobState.FAILED
            job.error = "analyzer restarted while job was in-flight"
            job.finished_at = _now()
            state.scan_job_store.append(job)
            recovered += 1
    if recovered:
        logger.warning("recovered %d stale scan job(s) to FAILED on startup", recovered)
    return recovered


def get_scan_semaphore(state: State) -> asyncio.Semaphore:
    """Return (creating once) the per-app scan concurrency semaphore."""
    sem = getattr(state, "scan_semaphore", None)
    if sem is None:
        sem = asyncio.Semaphore(_max_concurrent_scans())
        state.scan_semaphore = sem
    return sem


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
    a managed key on the analyzer host and is then discarded — never persisted.

    A ``transport=local`` target represents the analyzer's own host (scan in place,
    no SSH): it needs no credentials, so a password is rejected and any SSH credential
    fields are normalized away (credential_mode=none, identity_path=None)."""
    is_local = payload.transport == Transport.LOCAL
    if is_local and payload.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="local targets need no credentials; omit password",
        )
    # A local target is the analyzer host itself — it carries NO durable credential.
    # Don't persist dead/misleading SSH credential metadata for it (a direct API
    # caller may still send credential_mode=identity / identity_path).
    credential_mode = CredentialMode.NONE if is_local else payload.credential_mode
    identity_path = None if is_local else payload.identity_path
    # WinRM only supports the managed client-certificate path (no identity mode); the
    # admin UI enforces this, but the API must too (defense in depth — a direct caller
    # could otherwise persist a winrm+identity target that can never be scanned).
    if payload.transport == Transport.WINRM and credential_mode != CredentialMode.MANAGED_KEY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="WinRM targets only support managed-key (client certificate) credentials",
        )
    # A managed key is keyed by user@host:port (both at bootstrap and in the
    # credential manager). Reject a malformed address up front rather than persist
    # a target whose key can never be resolved/scanned/managed.
    if credential_mode == CredentialMode.MANAGED_KEY and not is_local:
        try:
            split_user_host(payload.address)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"managed-key targets need a user@host address: {exc}",
            ) from exc
    if payload.credential_mode == CredentialMode.MANAGED_KEY and payload.password:
        # SSH bootstraps a managed key into authorized_keys; WinRM bootstraps a
        # managed client certificate + WSMan mapping (its passwordless analog). Both
        # discard the one-time password after use.
        try:
            if payload.transport == Transport.SSH:
                await asyncio.to_thread(
                    bootstrap.ensure_key_auth, payload.address, payload.port, None, payload.password
                )
            elif payload.transport == Transport.WINRM:
                # skip_cert_check=True keeps the TLS posture consistent with the
                # rotate/revoke/trigger paths (WinRM HTTPS listeners are commonly
                # self-signed) — the trusted-lab stance, same as SSH AutoAddPolicy.
                await asyncio.to_thread(
                    winrm_bootstrap.ensure_cert_auth,
                    payload.address,
                    payload.port,
                    payload.password,
                    True,
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="managed-key bootstrap is supported for SSH and WinRM only",
                )
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001 - surface bootstrap failure to the caller
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"managed-credential bootstrap failed: {exc}",
            ) from exc

    target = ScanTarget(
        target_id=f"target-{uuid.uuid4()}",
        name=payload.name,
        address=payload.address,
        port=payload.port,
        transport=payload.transport,
        credential_mode=credential_mode,
        identity_path=identity_path,
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

    # Only SSH targets support trace/guard (they deploy a resident agent over SSH).
    # Local (in-place) and WinRM targets cover host asset collection only. Reject
    # early with a 4xx rather than creating a job the runner would only fail later.
    if target.transport != Transport.SSH and payload.capability != ScanCapability.HOST:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"capability {payload.capability.value} is not supported for "
                f"{target.transport.value} targets (host asset collection only)"
            ),
        )

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
    background.add_task(
        _run_job,
        request.app.state,
        job,
        target,
        _public_url(),
        get_scan_semaphore(request.app.state),
        _scan_job_timeout(),
    )
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


# --------------------------------------------- resident guard daemon lifecycle


def _resolve_guard_target(target_id: str, request: Request) -> ScanTarget:
    """Resolve a registered target and assert it can host a resident guard daemon."""
    record = request.app.state.scan_target_store.find_one("target_id", target_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    target = ScanTarget.model_validate(record)
    if target.transport != Transport.SSH:
        # guard is a remote resident daemon; local/winrm targets can't host one here.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"guard lifecycle is available only for SSH targets "
                f"(target transport is {target.transport.value})"
            ),
        )
    return target


@router.get("/targets/{target_id}/guard", response_model=GuardLifecycleStatus)
async def get_guard_status(target_id: str, request: Request) -> GuardLifecycleStatus:
    """Probe whether the resident guard daemon is alive on a target (常驻 status).

    Unreachable/auth failures degrade to ``alive=false`` rather than erroring, so a
    polling UI shows an honest "unknown/unreachable" instead of a hard failure.
    """
    target = _resolve_guard_target(target_id, request)
    try:
        st = await asyncio.to_thread(deploy_trigger.guard_status_for, target)
    except Exception as exc:  # noqa: BLE001 - report unreachable as a degraded status
        return GuardLifecycleStatus(
            target_id=target.target_id,
            address=target.address,
            alive=False,
            supervisor="unknown",
            detail=f"cannot reach target: {exc}",
        )
    return GuardLifecycleStatus(
        target_id=target.target_id,
        address=target.address,
        alive=st.alive,
        supervisor=st.supervisor,
        pid=st.pid,
        detail=st.detail,
    )


@router.post("/targets/{target_id}/guard/stop", response_model=GuardLifecycleStatus)
async def stop_guard(target_id: str, request: Request) -> GuardLifecycleStatus:
    """Stop + uninstall the resident guard daemon on a target (常驻 teardown)."""
    target = _resolve_guard_target(target_id, request)
    try:
        st = await asyncio.to_thread(deploy_trigger.stop_guard_for, target)
    except Exception as exc:  # noqa: BLE001 - a failed teardown is a 502, surfaced to admin
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"failed to stop guard daemon: {exc}",
        ) from exc
    return GuardLifecycleStatus(
        target_id=target.target_id,
        address=target.address,
        alive=st.alive,
        supervisor=st.supervisor,
        pid=st.pid,
        detail=st.detail,
    )


async def _execute_job(
    state: State,
    job: ScanJob,
    target: ScanTarget,
    public_url: str,
    timeout: float | None = None,
) -> None:
    """The actual deploy → ingest → record work for one job (off the event loop).

    ``timeout`` is the job's overall deadline; for a local scan it is plumbed into
    the agent-host subprocess so the child is actually killed if it overruns —
    ``asyncio.wait_for`` alone can only cancel the awaiting coroutine, not the
    blocking subprocess running in a thread-pool worker.
    """
    is_local = target.transport == Transport.LOCAL
    is_winrm = target.transport == Transport.WINRM
    if (is_local or is_winrm) and job.capability != ScanCapability.HOST:
        # trace/guard need a resident agent deployed over SSH; local/WinRM cover
        # host asset collection only.
        raise RuntimeError(
            f"capability {job.capability.value} is not supported for "
            f"{target.transport.value} targets (host asset collection only)"
        )

    if job.capability == ScanCapability.HOST:
        if is_local:
            report = await asyncio.to_thread(
                deploy_trigger.run_host_local, job.options, timeout
            )
        elif is_winrm:
            report = await asyncio.to_thread(deploy_trigger.run_host_winrm, target, job.options)
        else:
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
        # Pass the analyzer's bearer token so the daemon's uploads pass auth;
        # without it every GuardEventBatch is 401-rejected and silently lost.
        job.result = await asyncio.to_thread(
            deploy_trigger.run_guard, target, public_url, getattr(state, "api_token", None)
        )


async def _run_job(
    state: State,
    job: ScanJob,
    target: ScanTarget,
    public_url: str,
    semaphore: asyncio.Semaphore | None = None,
    timeout: float | None = None,
) -> None:
    """Background runner: deploy → ingest → record result. Never raises.

    E2: bounded by ``semaphore`` so only N scans run at once. B7: each run is
    bounded by ``timeout`` (``asyncio.wait_for``) so a hung SSH/target flips the
    job to FAILED instead of leaving it RUNNING forever.
    """
    if semaphore is None:
        semaphore = get_scan_semaphore(state)
    if timeout is None:
        timeout = _scan_job_timeout()

    async with semaphore:
        job.state = ScanJobState.RUNNING
        job.started_at = _now()
        state.scan_job_store.append(job)

        try:
            await asyncio.wait_for(
                _execute_job(state, job, target, public_url, timeout), timeout=timeout
            )
            job.state = ScanJobState.SUCCEEDED
        except TimeoutError:
            job.state = ScanJobState.FAILED
            job.error = f"scan job timed out after {timeout:g}s"
            logger.warning("scan job %s timed out after %gs", job.job_id, timeout)
        except Exception as exc:  # noqa: BLE001 - any failure is recorded on the job, not raised
            job.state = ScanJobState.FAILED
            job.error = str(exc)
        finally:
            job.finished_at = _now()
            state.scan_job_store.append(job)
