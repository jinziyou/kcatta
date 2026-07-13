"""Form-owned target registry + scan trigger/job API.

The admin calls Form to register targets and trigger remote scans. A trigger
creates a durable pending `ScanJob`; Form's lifespan-owned worker later claims
it with a fenced lease, deploys the agent, durably spools the artifact and
forwards it through Analyzer's private API. API requests never own execution.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import urlsplit

from analyzer.storage import StorageCapacityError
from fastapi import APIRouter, Header, HTTPException, Request, status
from starlette.datastructures import State

from ..agent_identity_store import AgentIdentityNotFoundError
from ..analyzer_client import AnalyzerClient
from ..deploy import bootstrap, winrm_bootstrap
from ..deploy import trigger as deploy_trigger
from ..deploy._util import remote_command_timeout_seconds, split_user_host
from ..deploy.winrm import winrm_skip_cert_check
from ..job_store import JobConflictError, JobNotFoundError, LeaseLostError
from ..provenance import bind_form_envelope
from ..public_url import normalize_public_origin
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

router = APIRouter(tags=["scans"])
logger = logging.getLogger("kcatta_form.api.scans")

# E2: cap concurrent in-process scan jobs so a batch trigger can't saturate the
# thread pool / overwhelm the box. Configurable; sensible default of 4.
DEFAULT_MAX_CONCURRENT_SCANS = 4
# B7: a job that hangs (dead SSH, unresponsive target) must not stay RUNNING
# forever — bound each run. Default 30 minutes; override via env.
DEFAULT_SCAN_JOB_TIMEOUT_SECONDS = 30 * 60
# Direct lifecycle mutations do not have the worker's heartbeat loop. Keep their
# durable target lease longer than the configured remote-operation budget so a
# concurrent worker/process cannot redeploy the Guard while stop is in flight.
MIN_TARGET_OPERATION_LEASE_SECONDS = 60.0
GUARD_STOP_MAX_REMOTE_COMMANDS = 3


def _trace_pcap_enabled() -> bool:
    """Whether this Form deployment carries a trace binary with libpcap support.

    The official static deploy binary deliberately contains only the real OS
    connection-table backend.  Operators that replace it with a custom
    ``pcap`` build must opt in explicitly so Form rejects unsupported jobs at
    submission time instead of accepting a task that can only fail remotely.
    """
    return os.getenv("FORM_TRACE_PCAP_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _max_concurrent_scans() -> int:
    raw = os.getenv("FORM_MAX_CONCURRENT_SCANS")
    try:
        value = int(raw) if raw else DEFAULT_MAX_CONCURRENT_SCANS
    except ValueError:
        value = DEFAULT_MAX_CONCURRENT_SCANS
    return max(1, value)


def _scan_job_timeout() -> float:
    raw = os.getenv("FORM_SCAN_JOB_TIMEOUT_SECONDS")
    try:
        value = float(raw) if raw else float(DEFAULT_SCAN_JOB_TIMEOUT_SECONDS)
    except ValueError:
        value = float(DEFAULT_SCAN_JOB_TIMEOUT_SECONDS)
    return max(1.0, value)


def _guard_stop_lease_ttl() -> timedelta:
    """Cover key probing plus every bounded SSH command in Guard teardown."""

    remote_budget = remote_command_timeout_seconds() * GUARD_STOP_MAX_REMOTE_COMMANDS
    return timedelta(
        seconds=(
            max(
                MIN_TARGET_OPERATION_LEASE_SECONDS,
                _scan_job_timeout(),
                remote_budget,
            )
            + MIN_TARGET_OPERATION_LEASE_SECONDS
        )
    )


def _now() -> datetime:
    return datetime.now(UTC)


def _public_url(agent_identity: bool = False) -> str:
    """Return a Form URL that a remote Guard can actually reach.

    A loopback default is actively dangerous here: it means the monitored host,
    not the Form host, once written into ``agentd --upload``. Require an explicit
    non-loopback HTTP(S) URL before accepting a resident Guard job.
    """
    agent_url = os.getenv("FORM_AGENT_PUBLIC_URL", "").strip()
    legacy_url = os.getenv("FORM_PUBLIC_URL", "").strip()
    value = agent_url if agent_identity else agent_url or legacy_url
    if not value:
        if agent_identity:
            raise ValueError(
                "FORM_AGENT_PUBLIC_URL is required for per-Agent mTLS Guard deployment; "
                "the legacy FORM_PUBLIC_URL control endpoint is not a certificate listener"
            )
        raise ValueError(
            "FORM_AGENT_PUBLIC_URL (or legacy FORM_PUBLIC_URL) is required before "
            "deploying a resident guard"
        )
    allow_insecure_http = os.getenv("FORM_ALLOW_INSECURE_HTTP", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    # The dedicated Agent endpoint is always mTLS and therefore always HTTPS.
    # Only the legacy token endpoint retains the explicit isolated-lab HTTP
    # escape hatch.
    value = normalize_public_origin(
        value,
        label="FORM_AGENT_PUBLIC_URL/FORM_PUBLIC_URL",
        allow_http=not agent_url and allow_insecure_http,
    )
    parsed = urlsplit(value)
    host = parsed.hostname.lower()
    if host == "localhost":
        raise ValueError(
            "FORM_AGENT_PUBLIC_URL/FORM_PUBLIC_URL must be reachable remotely, not localhost"
        )
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (address.is_loopback or address.is_unspecified):
        raise ValueError(
            "FORM_AGENT_PUBLIC_URL/FORM_PUBLIC_URL must be reachable remotely, not "
            "loopback/unspecified"
        )
    return value


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
    a managed key on the Form host and is then discarded — never persisted.

    A ``transport=local`` target represents Form's own host (scan in place,
    no SSH): it needs no credentials, so a password is rejected and any SSH credential
    fields are normalized away (credential_mode=none, identity_path=None)."""
    is_local = payload.transport == Transport.LOCAL
    if is_local and payload.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="local targets need no credentials; omit password",
        )
    # A local target is the Form host itself — it carries NO durable credential.
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
                await asyncio.to_thread(
                    winrm_bootstrap.ensure_cert_auth,
                    payload.address,
                    payload.port,
                    payload.password,
                    winrm_skip_cert_check(),
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
        canonical_host_id=payload.canonical_host_id,
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
    payload: TriggerScanRequest,
    request: Request,
    idempotency_key: Annotated[
        str | None,
        Header(alias="Idempotency-Key", max_length=256),
    ] = None,
) -> ScanJob:
    """Durably enqueue a scan; ``Idempotency-Key`` makes client retries safe."""
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if not idempotency_key:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Idempotency-Key must contain a non-whitespace value",
            )
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

    if (
        payload.capability == ScanCapability.TRACE
        and payload.options.pcap
        and not _trace_pcap_enabled()
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                "libpcap capture is unavailable in the official Form deploy binary; "
                "install a custom pcap-enabled agent-collect-trace and set "
                "FORM_TRACE_PCAP_ENABLED=true"
            ),
        )

    # Validate all non-persisted job prerequisites before appending PENDING.
    # Otherwise a rejected Guard URL would leave an undiscoverable ghost job
    # that no worker can ever execute.
    try:
        if payload.capability == ScanCapability.GUARD:
            _public_url(request.app.state.agent_identity_service is not None)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    if (
        payload.capability == ScanCapability.GUARD
        and request.app.state.agent_identity_service is None
        and not request.app.state.ingest_token
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Agent identity management or FORM_INGEST_TOKEN is required before "
                "deploying a resident guard"
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
        max_attempts=request.app.state.scan_worker.config.max_attempts,
    )
    fingerprint = hashlib.sha256(
        f"scan-request-v1:{payload.model_dump_json()}".encode()
    ).hexdigest()
    try:
        persisted, created = await asyncio.to_thread(
            request.app.state.scan_job_repository.create,
            job,
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint if idempotency_key is not None else None,
        )
    except JobConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except StorageCapacityError as exc:
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail=str(exc),
            headers={"Retry-After": "60"},
        ) from exc
    if created:
        request.app.state.scan_worker.notify()
    return persisted


@router.get("/scans", response_model=list[ScanJob])
async def list_scans(request: Request) -> list[ScanJob]:
    """List durable job heads, newest creation first."""
    return await asyncio.to_thread(request.app.state.scan_job_repository.list, 1000)


@router.get("/scans/{job_id}", response_model=ScanJob)
async def get_scan(job_id: str, request: Request) -> ScanJob:
    """Fetch a scan job (its latest state) by id."""
    job = await asyncio.to_thread(request.app.state.scan_job_repository.get, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan job not found")
    return job


@router.post(
    "/scans/{job_id}/cancel",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanJob,
)
async def cancel_scan(job_id: str, request: Request) -> ScanJob:
    """Cancel queued work immediately or request cooperative active cleanup."""
    try:
        job = await asyncio.to_thread(
            request.app.state.scan_job_repository.request_cancel,
            job_id,
            _now(),
        )
    except JobNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if job.state == ScanJobState.CANCELLED:
        try:
            await asyncio.to_thread(request.app.state.scan_artifact_store.delete, job_id)
        except Exception:  # noqa: BLE001 - durable reconcile retries cleanup on restart
            logger.exception("cannot delete cancelled scan artifact %s", job_id)
    request.app.state.scan_worker.notify_cancel(job_id)
    return job


@router.post(
    "/scans/{job_id}/retry",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanJob,
)
async def retry_scan(job_id: str, request: Request) -> ScanJob:
    """Explicitly reset one failed/cancelled durable job and requeue it."""
    try:
        job = await asyncio.to_thread(
            request.app.state.scan_job_repository.manual_retry,
            job_id,
            _now(),
        )
    except JobNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except JobConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    request.app.state.scan_worker.notify()
    return job


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
    """Revoke Guard leaf certificates, then best-effort stop the remote daemon.

    The durable target-operation lease serializes this direct API mutation with
    scan workers in every Form process. Certificate revocation deliberately
    precedes SSH teardown: an unreachable or immediately respawned daemon must
    not retain a valid mTLS identity.
    """
    target = _resolve_guard_target(target_id, request)
    repository = request.app.state.scan_job_repository
    lease = await asyncio.to_thread(
        repository.acquire_target_operation,
        target.target_id,
        f"guard-stop:{uuid.uuid4().hex}",
        _now(),
        _guard_stop_lease_ttl(),
    )
    if lease is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "target is busy with an active scan or another lifecycle operation; "
                "retry Guard stop after it finishes"
            ),
        )

    lease_ttl = _guard_stop_lease_ttl()
    try:
        try:
            lease = await asyncio.to_thread(
                repository.renew_target_operation,
                lease,
                _now(),
                lease_ttl,
            )
        except LeaseLostError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="target operation lease expired before certificate revocation",
            ) from exc

        revocation_error: Exception | None = None
        identity_service = request.app.state.agent_identity_service
        if identity_service is not None:
            try:
                identity = await asyncio.to_thread(
                    identity_service.repository.get_by_target,
                    target.target_id,
                )
                await asyncio.to_thread(
                    identity_service.revoke_certificates,
                    identity.agent_id,
                )
            except AgentIdentityNotFoundError:
                # No registered identity means there is no managed leaf to revoke.
                pass
            except Exception as exc:  # noqa: BLE001 - still attempt remote containment
                revocation_error = exc

        remote_error: Exception | None = None
        st = None
        try:
            lease = await asyncio.to_thread(
                repository.renew_target_operation,
                lease,
                _now(),
                lease_ttl,
            )
            st = await asyncio.to_thread(deploy_trigger.stop_guard_for, target)
        except LeaseLostError:
            remote_error = RuntimeError(
                "target operation lease expired after certificate revocation; "
                "remote stop was not attempted"
            )
        except Exception as exc:  # noqa: BLE001 - report after preserving revocation outcome
            remote_error = exc

        if revocation_error is not None or remote_error is not None:
            failures: list[str] = []
            if revocation_error is not None:
                failures.append(f"failed to revoke Agent certificates: {revocation_error}")
            if remote_error is not None:
                failures.append(f"failed to stop guard daemon: {remote_error}")
            elif st is not None:
                remote_outcome = (
                    "remote guard still reports alive" if st.alive else "remote guard stopped"
                )
                failures.append(f"{remote_outcome}: {st.detail}")
            raise HTTPException(
                status_code=(
                    status.HTTP_503_SERVICE_UNAVAILABLE
                    if revocation_error is not None
                    else status.HTTP_502_BAD_GATEWAY
                ),
                detail="; ".join(failures),
            )

        assert st is not None
        return GuardLifecycleStatus(
            target_id=target.target_id,
            address=target.address,
            alive=st.alive,
            supervisor=st.supervisor,
            pid=st.pid,
            detail=st.detail,
        )
    finally:
        try:
            await asyncio.to_thread(repository.release_target_operation, lease)
        except LeaseLostError:
            # Expiry/reclamation is already reflected by the response path. A
            # stale release must never replace a more useful 2xx/4xx/5xx result.
            logger.warning("Guard stop lost target operation lease for %s", target.target_id)


async def _execute_job(
    state: State,
    job: ScanJob,
    target: ScanTarget,
    public_url: str,
    analyzer_client: AnalyzerClient,
    timeout: float | None = None,
) -> None:
    """Compatibility helper for direct one-shot execution in transport tests.

    Production jobs use :class:`kcatta_form.scan_worker.ScanJobWorker`, including
    leases, durable artifact handoff and fencing. ``timeout`` is still plumbed
    into the local subprocess here so the legacy focused tests remain bounded.
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
            report = await asyncio.to_thread(deploy_trigger.run_host_local, job.options, timeout)
        elif is_winrm:
            report = await asyncio.to_thread(deploy_trigger.run_host_winrm, target, job.options)
        else:
            report = await asyncio.to_thread(deploy_trigger.run_host, target, job.options)
        report = bind_form_envelope(
            report,
            target_id=target.target_id,
            canonical_host_id=target.canonical_host_id or target.target_id,
        )
        await analyzer_client.ingest_asset_report(report)
        job.result = ScanResult(
            kind=ScanCapability.HOST, report_id=report.report_id, host_id=report.host.host_id
        )
    elif job.capability == ScanCapability.TRACE:
        batch = await asyncio.to_thread(deploy_trigger.run_trace, target, job.options)
        batch = bind_form_envelope(
            batch,
            target_id=target.target_id,
            canonical_host_id=target.canonical_host_id or target.target_id,
        )
        await analyzer_client.ingest_trace_batch(batch)
        job.result = ScanResult(kind=ScanCapability.TRACE, batch_id=batch.batch_id)
    else:  # guard: starts a persistent daemon that uploads its own events
        identity_service = getattr(state, "agent_identity_service", None)
        if identity_service is not None:
            staged = await asyncio.to_thread(
                identity_service.stage_for_target,
                target.target_id,
                target.canonical_host_id or target.target_id,
                ["guard-event"],
                idempotency_key=f"{job.job_id}:compat",
            )
            if staged.bundle is None:
                raise RuntimeError("Agent certificate deployment material is unavailable")
            try:

                def activate_generation() -> None:
                    identity_service.activate(
                        staged.identity.agent_id,
                        staged.certificate.generation,
                    )

                job.result = await asyncio.to_thread(
                    deploy_trigger.run_guard,
                    target,
                    public_url,
                    None,
                    staged.bundle,
                    activate_generation,
                )
            except BaseException:
                with contextlib.suppress(BaseException):
                    await asyncio.to_thread(
                        identity_service.abort,
                        staged.identity.agent_id,
                        staged.certificate.generation,
                    )
                raise
        else:
            # Legacy migration path: only the ingest-scoped token is eligible;
            # the control credential can never reach an endpoint.
            guard_token = getattr(state, "ingest_token", None)
            if not guard_token:
                raise RuntimeError(
                    "Agent identity management and FORM_INGEST_TOKEN are unavailable"
                )
            job.result = await asyncio.to_thread(
                deploy_trigger.run_guard, target, public_url, guard_token
            )
