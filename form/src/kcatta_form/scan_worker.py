"""Lease-backed durable scan worker owned by Form's application lifespan.

The repository provides cross-process claim/fencing. This module owns only the
execution loop: resolve the current target, collect once, durably spool the
artifact, forward it to Analyzer, and commit a terminal/retry state while the
same lease is still valid.

Execution is intentionally documented as *at least once*. A lease prevents an
old worker from overwriting a newer state, but a process can still die after a
remote side effect. The durable artifact spool and stable report identifiers
make the common collect-complete/forward-failed window idempotent.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import math
import os
import random
import socket
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from analyzer.storage import StorageCapacityError
from starlette.datastructures import State

from .agent_identity_store import AgentIdentityNotFoundError
from .analyzer_client import AnalyzerUpstreamError
from .deploy import trigger as deploy_trigger
from .job_store import ClaimedScanJob, LeaseLostError, ScanJobRepository
from .provenance import bind_form_envelope
from .scan_artifacts import ScanArtifactStore
from .schemas import (
    AgentCertificateState,
    AgentScope,
    AssetReport,
    ScanCapability,
    ScanJob,
    ScanJobState,
    ScanResult,
    ScanTarget,
    TraceBatch,
    Transport,
)

logger = logging.getLogger("kcatta_form.scan_worker")

DEFAULT_MAX_CONCURRENT_SCANS = 4
DEFAULT_SCAN_JOB_TIMEOUT_SECONDS = 30 * 60
DEFAULT_LEASE_SECONDS = 60.0
DEFAULT_HEARTBEAT_SECONDS = 15.0
DEFAULT_POLL_SECONDS = 1.0
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_RETRY_BASE_SECONDS = 5.0
DEFAULT_RETRY_MAX_SECONDS = 5 * 60.0
DEFAULT_SHUTDOWN_GRACE_SECONDS = 15.0
DEFAULT_SPOOL_RECONCILE_SECONDS = 60.0
_TRANSIENT_ANALYZER_STATUSES = {408, 425, 429, 500, 502, 503, 504, 507}


def _positive_int_env(name: str, default: int, *, maximum: int | None = None) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        value = default
    if value <= 0:
        value = default
    return min(value, maximum) if maximum is not None else value


def _positive_float_env(name: str, default: float) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError:
        value = default
    return value if math.isfinite(value) and value > 0 else default


@dataclass(frozen=True)
class ScanWorkerConfig:
    """Validated scheduling and retry parameters for one Form instance."""

    concurrency: int = DEFAULT_MAX_CONCURRENT_SCANS
    job_timeout_seconds: float = DEFAULT_SCAN_JOB_TIMEOUT_SECONDS
    lease_seconds: float = DEFAULT_LEASE_SECONDS
    heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS
    poll_seconds: float = DEFAULT_POLL_SECONDS
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    retry_base_seconds: float = DEFAULT_RETRY_BASE_SECONDS
    retry_max_seconds: float = DEFAULT_RETRY_MAX_SECONDS
    shutdown_grace_seconds: float = DEFAULT_SHUTDOWN_GRACE_SECONDS

    def __post_init__(self) -> None:
        if self.concurrency <= 0 or self.max_attempts <= 0:
            raise ValueError("worker concurrency and max_attempts must be positive")
        if self.max_attempts > 20:
            raise ValueError("worker max_attempts cannot exceed the public contract limit 20")
        if (
            min(
                self.job_timeout_seconds,
                self.lease_seconds,
                self.heartbeat_seconds,
                self.poll_seconds,
                self.retry_base_seconds,
                self.retry_max_seconds,
                self.shutdown_grace_seconds,
            )
            <= 0
        ):
            raise ValueError("worker time settings must be positive")
        if self.heartbeat_seconds >= self.lease_seconds:
            raise ValueError("worker heartbeat must be shorter than its lease")
        if self.retry_base_seconds > self.retry_max_seconds:
            raise ValueError("retry base cannot exceed retry maximum")

    @classmethod
    def from_env(cls) -> ScanWorkerConfig:
        lease = _positive_float_env("FORM_SCAN_LEASE_SECONDS", DEFAULT_LEASE_SECONDS)
        heartbeat_default = min(DEFAULT_HEARTBEAT_SECONDS, lease / 3)
        return cls(
            concurrency=_positive_int_env(
                "FORM_MAX_CONCURRENT_SCANS", DEFAULT_MAX_CONCURRENT_SCANS
            ),
            job_timeout_seconds=_positive_float_env(
                "FORM_SCAN_JOB_TIMEOUT_SECONDS", DEFAULT_SCAN_JOB_TIMEOUT_SECONDS
            ),
            lease_seconds=lease,
            heartbeat_seconds=_positive_float_env("FORM_SCAN_HEARTBEAT_SECONDS", heartbeat_default),
            poll_seconds=_positive_float_env("FORM_SCAN_POLL_SECONDS", DEFAULT_POLL_SECONDS),
            max_attempts=_positive_int_env(
                "FORM_SCAN_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS, maximum=20
            ),
            retry_base_seconds=_positive_float_env(
                "FORM_SCAN_RETRY_BASE_SECONDS", DEFAULT_RETRY_BASE_SECONDS
            ),
            retry_max_seconds=_positive_float_env(
                "FORM_SCAN_RETRY_MAX_SECONDS", DEFAULT_RETRY_MAX_SECONDS
            ),
            shutdown_grace_seconds=_positive_float_env(
                "FORM_SCAN_SHUTDOWN_GRACE_SECONDS", DEFAULT_SHUTDOWN_GRACE_SECONDS
            ),
        )


@dataclass
class ExecutionControl:
    """Cooperative signal checked between blocking deploy/forward phases."""

    cancel_requested: asyncio.Event = field(default_factory=asyncio.Event)
    timed_out: asyncio.Event = field(default_factory=asyncio.Event)
    shutting_down: asyncio.Event = field(default_factory=asyncio.Event)
    lease_lost: asyncio.Event = field(default_factory=asyncio.Event)
    guard_side_effect_committed: bool = False
    guard_agent_id: str | None = None
    guard_generation: int | None = None
    guard_deployment_manifest: deploy_trigger.GuardDeploymentManifest | None = None
    guard_cleanup_pending: bool = False
    guard_side_effect_compensated: bool = False

    @property
    def interrupted(self) -> bool:
        return any(
            event.is_set()
            for event in (
                self.cancel_requested,
                self.timed_out,
                self.shutting_down,
                self.lease_lost,
            )
        )


class ScanExecutionInterrupted(RuntimeError):
    """A cooperative phase boundary observed cancellation/timeout/shutdown."""


class GuardReconciliationRequired(RuntimeError):
    """A Guard mutation cannot be terminally committed until its manifest is reconciled."""


class ScanJobWorker:
    """Poll, claim and execute durable scan jobs up to a global repository cap."""

    def __init__(
        self,
        state: State,
        repository: ScanJobRepository,
        artifacts: ScanArtifactStore,
        *,
        public_url_resolver: Callable[[bool], str],
        config: ScanWorkerConfig | None = None,
        worker_id: str | None = None,
        random_source: random.Random | None = None,
    ) -> None:
        self.state = state
        self.repository = repository
        self.artifacts = artifacts
        self.public_url_resolver = public_url_resolver
        self.config = config or ScanWorkerConfig.from_env()
        hostname = socket.gethostname().split(".", 1)[0][:64]
        self.worker_id = worker_id or f"{hostname}:{os.getpid()}:{uuid.uuid4().hex}"
        self._random = random_source or random.Random()
        self._wake = asyncio.Event()
        self._stopping = False
        self._loop_task: asyncio.Task[None] | None = None
        self._last_loop_error: str | None = None
        self._next_reconcile_at = 0.0
        self._active: dict[str, asyncio.Task[None]] = {}
        self._controls: dict[str, ExecutionControl] = {}

    @property
    def running(self) -> bool:
        return self._loop_task is not None and not self._loop_task.done()

    @property
    def active_count(self) -> int:
        return len(self._active)

    @property
    def healthy(self) -> bool:
        """Whether the poll loop is alive and its last repository pass succeeded."""
        return self.running and self._last_loop_error is None

    async def start(self) -> None:
        if self.running:
            return
        self._stopping = False
        self._last_loop_error = None
        self._next_reconcile_at = 0.0
        self._loop_task = asyncio.create_task(
            self._run_loop(), name=f"form-scan-worker:{self.worker_id}"
        )
        self.notify()

    def notify(self) -> None:
        """Wake the poll loop after a new/cancelled/retried job is committed."""
        self._wake.set()

    def notify_cancel(self, job_id: str) -> None:
        """Immediately signal a cancellation handled by this Form instance.

        The durable state remains authoritative and heartbeat polling covers
        cancellation received by another replica. This local fast path closes
        the collection-complete/forward-start race for the common case.
        """
        control = self._controls.get(job_id)
        if control is not None:
            control.cancel_requested.set()
        self.notify()

    async def stop(self) -> None:
        """Stop claiming, signal active work, and wait a bounded graceful period."""
        self._stopping = True
        for control in self._controls.values():
            control.shutting_down.set()
        self.notify()
        if self._loop_task is not None:
            await self._loop_task
            self._loop_task = None
        tasks = list(self._active.values())
        if not tasks:
            return
        _, pending = await asyncio.wait(tasks, timeout=self.config.shutdown_grace_seconds)
        if pending:
            logger.warning(
                "scan worker shutdown grace expired with %d execution(s); leases remain",
                len(pending),
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def _run_loop(self) -> None:
        failures = 0
        while not self._stopping:
            self._wake.clear()
            try:
                await self._dispatch_available()
                await self._reconcile_artifacts_if_due()
            except Exception as exc:  # noqa: BLE001 - durable work must survive DB outages
                failures += 1
                self._last_loop_error = str(exc)
                delay = min(30.0, self.config.poll_seconds * (2 ** min(failures - 1, 10)))
                logger.exception(
                    "scan worker poll failed; retrying durable queue in %.2fs",
                    delay,
                )
                if self._stopping:
                    break
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), timeout=delay)
                continue
            failures = 0
            self._last_loop_error = None
            if self._stopping:
                break
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=self.config.poll_seconds)

    async def _reconcile_artifacts_if_due(self) -> None:
        now = asyncio.get_running_loop().time()
        if now < self._next_reconcile_at:
            return
        removed = await asyncio.to_thread(
            self.artifacts.reconcile,
            self.repository.retains_artifact,
        )
        self._next_reconcile_at = now + DEFAULT_SPOOL_RECONCILE_SECONDS
        if removed:
            logger.info("removed %d stale scan spool artifact(s)", removed)

    async def _dispatch_available(self) -> None:
        while not self._stopping and len(self._active) < self.config.concurrency:
            claim = await asyncio.to_thread(
                self.repository.claim_next,
                self.worker_id,
                datetime.now(UTC),
                timedelta(seconds=self.config.lease_seconds),
                self.config.concurrency,
                tuple(self._active),
            )
            if claim is None:
                return
            job_id = claim.job.job_id
            if job_id in self._active:
                logger.error("repository returned an already-active job %s", job_id)
                return
            control = ExecutionControl()
            if claim.job.state == ScanJobState.CANCELLING:
                control.cancel_requested.set()
            self._controls[job_id] = control
            task = asyncio.create_task(
                self._process_claim(claim, control),
                name=f"form-scan:{job_id}",
            )
            self._active[job_id] = task
            task.add_done_callback(lambda done, jid=job_id: self._execution_done(jid, done))

    def _execution_done(self, job_id: str, task: asyncio.Task[None]) -> None:
        self._active.pop(job_id, None)
        self._controls.pop(job_id, None)
        if not task.cancelled() and (error := task.exception()) is not None:
            logger.error(
                "unhandled scan worker error for %s",
                job_id,
                exc_info=(type(error), error, error.__traceback__),
            )
        self.notify()

    async def _process_claim(
        self,
        initial_claim: ClaimedScanJob,
        control: ExecutionControl,
    ) -> None:
        execution = asyncio.create_task(self._execute(initial_claim.job, control))
        timeout_marker = asyncio.create_task(self._mark_timeout(initial_claim.job.job_id, control))
        try:
            await self._finish_claim(initial_claim, control, execution)
        finally:
            # `_execute` is a separate task so heartbeat monitoring can run in
            # parallel. A forced application shutdown cancels this parent; it
            # must also cancel and reap the child before app lifespan closes
            # Analyzer/repository dependencies. An underlying `to_thread` call
            # may finish later, but its cancelled coroutine cannot spool/forward.
            if not execution.done():
                control.shutting_down.set()
                execution.cancel()
            timeout_marker.cancel()
            await asyncio.gather(execution, return_exceptions=True)
            await asyncio.gather(timeout_marker, return_exceptions=True)

    async def _mark_timeout(self, job_id: str, control: ExecutionControl) -> None:
        await asyncio.sleep(self.config.job_timeout_seconds)
        if not control.timed_out.is_set():
            control.timed_out.set()
            logger.warning(
                "scan job %s exceeded %.1fs; waiting for the bounded transport to stop",
                job_id,
                self.config.job_timeout_seconds,
            )

    async def _finish_claim(
        self,
        initial_claim: ClaimedScanJob,
        control: ExecutionControl,
        execution: asyncio.Task[ScanResult],
    ) -> None:
        claim = initial_claim
        error: BaseException | None = None
        result: ScanResult | None = None

        claim = await self._heartbeat_until_done(claim, control, execution)

        try:
            result = await execution
        except BaseException as exc:  # includes CancelledError during forced app shutdown
            error = exc

        # An uncertain deploy deliberately retains its staged generation. Do not
        # turn the durable head into RETRYING/FAILED: an expired RUNNING lease is
        # what lets the next fenced owner reconcile the remote manifest first.
        if isinstance(
            error,
            (deploy_trigger.GuardDeploymentUncertainError, GuardReconciliationRequired),
        ):
            logger.warning(
                "scan job %s requires Guard deployment reconciliation: %s",
                claim.job.job_id,
                error,
            )
            return

        # Close the completion-vs-cancel race: execution may finish between two
        # heartbeat ticks, so refresh the fenced head once before choosing a
        # terminal transition.
        if not control.lease_lost.is_set():
            try:
                claim = await asyncio.to_thread(
                    self.repository.renew,
                    claim,
                    datetime.now(UTC),
                    timedelta(seconds=self.config.lease_seconds),
                )
            except LeaseLostError:
                control.lease_lost.set()
            except Exception:  # noqa: BLE001 - leave the lease for expiry/recovery
                logger.exception(
                    "cannot refresh scan-job lease before completion for %s",
                    claim.job.job_id,
                )
                return
            if claim.job.state == ScanJobState.CANCELLING:
                control.cancel_requested.set()

        if control.lease_lost.is_set():
            return

        # Cancellation observed only after the deploy task returned still owns
        # the same fenced target lease. Run compensation as a monitored task so
        # slow SSH teardown does not let that lease silently expire.
        if (
            control.cancel_requested.is_set()
            and control.guard_side_effect_committed
            and not control.guard_side_effect_compensated
        ):
            cleanup = asyncio.create_task(self._compensate_guard_if_needed(claim.job, control))
            claim = await self._heartbeat_until_done(claim, control, cleanup)
            cleanup_error = await cleanup
            if control.lease_lost.is_set() or cleanup_error is not None:
                if cleanup_error is not None:
                    logger.error(
                        "Guard cancellation for %s remains pending: %s",
                        claim.job.job_id,
                        cleanup_error,
                    )
                return

        # Never release a shutting-down execution as RETRYING. In particular,
        # the final attempt may already have spooled an artifact. Keeping the
        # fenced head RUNNING until lease expiry gives the capped max+1 claim a
        # chance to hand that durable result off without recollection.
        if (
            control.shutting_down.is_set()
            and not control.cancel_requested.is_set()
            and result is None
        ):
            return

        now = datetime.now(UTC)
        latest = claim.job.model_copy(deep=True)
        latest.updated_at = now
        latest.available_at = None
        delete_artifact_after_commit = False

        # Once Analyzer has acknowledged a host/trace envelope, the durable
        # result exists and cannot be revoked. Record SUCCEEDED even if cancel
        # raced with the in-flight HTTP request; otherwise Admin would claim no
        # result while Analyzer already stores one. Guard cancellation still
        # wins after its resident side effect has been compensated above.
        if result is not None and latest.capability != ScanCapability.GUARD:
            latest.state = ScanJobState.SUCCEEDED
            latest.result = result
            latest.error = None
            latest.finished_at = now
            delete_artifact_after_commit = True
        elif control.cancel_requested.is_set() or latest.state == ScanJobState.CANCELLING:
            latest.finished_at = now
            latest.state = ScanJobState.CANCELLED
            latest.error = "scan cancelled by operator"
            delete_artifact_after_commit = True
        elif result is not None:
            latest.state = ScanJobState.SUCCEEDED
            latest.result = result
            latest.error = None
            latest.finished_at = now
            delete_artifact_after_commit = True
        elif control.timed_out.is_set():
            self._set_failure_or_retry(
                latest,
                now,
                "scan job exceeded its execution timeout",
                True,
            )
        elif error is not None:
            retryable = _retryable(error)
            # Guard deployment owns its own remote transaction and restores the
            # previous generation on a confirmed failure. An uncertain rollback
            # returned above and remains RUNNING for manifest reconciliation.
            self._set_failure_or_retry(
                latest,
                now,
                _bounded_error(str(error)),
                retryable,
            )
        else:
            self._set_failure_or_retry(latest, now, "scan execution produced no result", False)

        if latest.state == ScanJobState.FAILED:
            # A terminal failure must not pin a corrupt/permanent artifact and
            # eventually exhaust the global spool. Manual retry recollects.
            delete_artifact_after_commit = True

        try:
            await asyncio.to_thread(self.repository.complete, claim, latest)
        except LeaseLostError:
            # request_cancel may win in the tiny window after the final renew.
            # Re-prove this lease before mutating the remote target, then perform
            # the same heartbeat-protected compensation immediately.
            await self._handle_completion_cancel_race(claim, control)
        else:
            if delete_artifact_after_commit:
                await asyncio.to_thread(self.artifacts.delete, latest.job_id)

    async def _heartbeat_until_done(
        self,
        claim: ClaimedScanJob,
        control: ExecutionControl,
        execution: asyncio.Task[Any],
    ) -> ClaimedScanJob:
        """Renew the fenced job lease while one execution/compensation task runs."""

        while not execution.done():
            done, _ = await asyncio.wait(
                {execution},
                timeout=max(0.01, self.config.heartbeat_seconds),
            )
            if done:
                break
            try:
                claim = await asyncio.to_thread(
                    self.repository.renew,
                    claim,
                    datetime.now(UTC),
                    timedelta(seconds=self.config.lease_seconds),
                )
            except LeaseLostError:
                control.lease_lost.set()
                logger.warning("scan job %s lost lease fencing", claim.job.job_id)
            except Exception:  # noqa: BLE001 - retain the slot while a DB outage may recover
                logger.exception("cannot renew scan-job lease for %s", claim.job.job_id)
                if datetime.now(UTC) >= claim.lease_expires_at:
                    control.lease_lost.set()
            if claim.job.state == ScanJobState.CANCELLING:
                control.cancel_requested.set()
        return claim

    async def _handle_completion_cancel_race(
        self,
        claim: ClaimedScanJob,
        control: ExecutionControl,
    ) -> None:
        """Compensate when cancellation wins after the last pre-complete renew."""

        try:
            claim = await asyncio.to_thread(
                self.repository.renew,
                claim,
                datetime.now(UTC),
                timedelta(seconds=self.config.lease_seconds),
            )
        except LeaseLostError:
            logger.warning("discarded fenced terminal update for %s", claim.job.job_id)
            return
        if claim.job.state != ScanJobState.CANCELLING:
            logger.warning("discarded fenced terminal update for %s", claim.job.job_id)
            return
        control.cancel_requested.set()
        if control.guard_side_effect_committed and not control.guard_side_effect_compensated:
            cleanup = asyncio.create_task(self._compensate_guard_if_needed(claim.job, control))
            claim = await self._heartbeat_until_done(claim, control, cleanup)
            cleanup_error = await cleanup
            if control.lease_lost.is_set() or cleanup_error is not None:
                return
        cancelled = claim.job.model_copy(deep=True)
        cancelled.state = ScanJobState.CANCELLED
        cancelled.result = None
        cancelled.error = "scan cancelled by operator"
        cancelled.updated_at = datetime.now(UTC)
        cancelled.finished_at = cancelled.updated_at
        cancelled.available_at = None
        try:
            await asyncio.to_thread(self.repository.complete, claim, cancelled)
        except LeaseLostError:
            logger.warning("discarded fenced cancellation update for %s", claim.job.job_id)
        else:
            await asyncio.to_thread(self.artifacts.delete, claim.job.job_id)

    async def _compensate_guard_if_needed(
        self,
        job: ScanJob,
        control: ExecutionControl,
    ) -> str | None:
        if job.capability != ScanCapability.GUARD:
            return None
        errors: list[str] = []
        expected_manifest = control.guard_deployment_manifest
        if expected_manifest is None:
            return "Guard deployment manifest is not proven for this job"
        # Revoke only the generation proven to belong to this job. Revoking all
        # target credentials could disable an unrelated healthy deployment.
        # Do not remove the manifest before a failed revocation can be retried.
        identity_service = getattr(self.state, "agent_identity_service", None)
        if identity_service is not None:
            if control.guard_agent_id is None or control.guard_generation is None:
                return "Guard certificate generation is not proven by the deployment manifest"
            try:
                await asyncio.to_thread(
                    identity_service.revoke,
                    control.guard_agent_id,
                    generation=control.guard_generation,
                )
            except Exception as exc:  # noqa: BLE001 - cleanup remains durably pending
                return f"Agent credential revocation failed: {exc}"
        try:
            target_record = await asyncio.to_thread(
                self.state.scan_target_store.find_one,
                "target_id",
                job.target_id,
            )
        except Exception as exc:  # noqa: BLE001 - cleanup remains durably pending
            return f"target lookup failed: {exc}"
        if target_record is None:
            errors.append(f"target {job.target_id} no longer exists")
        else:
            try:
                target = ScanTarget.model_validate(target_record)
                status = await asyncio.to_thread(
                    deploy_trigger.stop_guard_for,
                    target,
                    expected_manifest=expected_manifest,
                )
            except Exception as exc:  # noqa: BLE001 - returned into durable job state
                errors.append(f"remote Guard teardown failed: {exc}")
            else:
                if status.alive:
                    errors.append(status.detail or "guard still reports alive")
        if errors:
            return "; ".join(errors)
        control.guard_cleanup_pending = False
        control.guard_side_effect_compensated = True
        return None

    async def _reconcile_guard_deployment(
        self,
        job: ScanJob,
        target: ScanTarget,
        control: ExecutionControl,
        *,
        include_current_attempt: bool,
        activate_staged: bool,
        allow_revoked: bool = False,
    ) -> tuple[ScanResult | None, bool]:
        """Match one job-owned certificate generation to manifest and live PID.

        Returns ``(result, unresolved)``. ``unresolved`` means this job still has
        durable certificate metadata but Form cannot prove whether its remote
        side effect committed; callers must keep the leased head non-terminal.
        """

        identity_service = getattr(self.state, "agent_identity_service", None)
        if identity_service is None:
            return None, False
        try:
            identity = await asyncio.to_thread(
                identity_service.repository.get_by_target,
                job.target_id,
            )
        except AgentIdentityNotFoundError:
            return None, False
        except Exception as exc:  # noqa: BLE001 - central proof must remain retryable
            raise GuardReconciliationRequired(
                f"cannot read Agent identity for Guard reconciliation: {exc}"
            ) from exc

        last_attempt = job.attempt if include_current_attempt else job.attempt - 1
        candidates: list[Any] = []
        allowed_states = {
            AgentCertificateState.STAGED,
            AgentCertificateState.ACTIVE,
        }
        if allow_revoked:
            allowed_states.add(AgentCertificateState.REVOKED)
        try:
            for attempt in range(last_attempt, 0, -1):
                certificate = await asyncio.to_thread(
                    identity_service.repository.get_by_idempotency_key,
                    identity.agent_id,
                    f"{job.job_id}:attempt:{attempt}",
                )
                if certificate is not None and certificate.state in allowed_states:
                    candidates.append(certificate)
        except Exception as exc:  # noqa: BLE001 - retain the capped reconciliation claim
            raise GuardReconciliationRequired(
                f"cannot read job-owned Agent certificate generation: {exc}"
            ) from exc
        if not candidates:
            return None, False

        try:
            proof = await asyncio.to_thread(
                deploy_trigger.guard_deployment_proof_for,
                target,
            )
            manifest = proof.manifest
            status = proof.status
        except Exception as exc:  # noqa: BLE001 - retain RUNNING for a later fenced probe
            raise GuardReconciliationRequired(
                f"cannot inspect Guard deployment manifest for {job.target_id}: {exc}"
            ) from exc
        if manifest is None:
            if status.alive:
                return None, True
            staged = [
                certificate
                for certificate in candidates
                if certificate.state is AgentCertificateState.STAGED
            ]
            committed = [
                certificate
                for certificate in candidates
                if certificate.state is not AgentCertificateState.STAGED
            ]
            # A crash may happen after the one-time bundle is staged but before
            # the first remote mutation. Manifest absence plus a positive dead
            # probe under the deployment proof is the only state in which that
            # unused generation can be discarded safely. ACTIVE/REVOKED
            # candidates still represent a committed lineage and remain
            # unresolved rather than authorizing a blind redeploy.
            try:
                for certificate in staged:
                    await asyncio.to_thread(
                        identity_service.abort,
                        identity.agent_id,
                        certificate.generation,
                    )
            except Exception as exc:  # noqa: BLE001 - retry central cleanup in place
                raise GuardReconciliationRequired(
                    f"cannot abort unused staged Agent generation: {exc}"
                ) from exc
            return None, bool(committed)

        matched = next(
            (
                certificate
                for certificate in candidates
                if manifest.identity_generation
                == f"generation-{certificate.generation}-{certificate.cert_sha256[:16]}"
            ),
            None,
        )
        live_pid = str(status.pid or "")
        if matched is None or not status.alive or not live_pid or manifest.pid != live_pid:
            return None, True

        control.guard_side_effect_committed = True
        control.guard_agent_id = identity.agent_id
        control.guard_generation = matched.generation
        control.guard_deployment_manifest = manifest
        control.guard_cleanup_pending = matched.state is AgentCertificateState.REVOKED
        if matched.state is AgentCertificateState.STAGED and activate_staged:
            try:
                await asyncio.to_thread(
                    identity_service.activate,
                    identity.agent_id,
                    matched.generation,
                )
            except Exception as exc:  # noqa: BLE001 - remote commit remains authoritative
                raise GuardReconciliationRequired(
                    f"cannot activate reconciled Agent generation: {exc}"
                ) from exc
        return (
            ScanResult(
                kind=ScanCapability.GUARD,
                host_id=target.canonical_host_id or target.target_id,
                pid=manifest.pid,
                detail="guard deployment recovered from its validated remote manifest",
            ),
            False,
        )

    async def _bind_legacy_guard_deployment(
        self,
        target: ScanTarget,
        artifact: ScanResult,
        control: ExecutionControl,
    ) -> None:
        """Bind a legacy Guard result to one exact, identity-less remote proof."""

        proof = await asyncio.to_thread(
            deploy_trigger.guard_deployment_proof_for,
            target,
        )
        manifest = proof.manifest
        status = proof.status
        artifact_pid = str(artifact.pid or "")
        if (
            artifact.kind != ScanCapability.GUARD
            or manifest is None
            or manifest.identity_generation is not None
            or not status.alive
            or not artifact_pid
            or manifest.pid != artifact_pid
            or str(status.pid or "") != artifact_pid
        ):
            raise GuardReconciliationRequired(
                "legacy Guard result is not backed by its exact live manifest"
            )
        control.guard_side_effect_committed = True
        control.guard_deployment_manifest = manifest

    def _set_failure_or_retry(
        self,
        job: ScanJob,
        now: datetime,
        error: str,
        retryable: bool,
    ) -> None:
        job.error = _bounded_error(error)
        job.result = None
        if retryable and job.attempt < job.max_attempts:
            exponent = max(0, job.attempt - 1)
            delay = min(
                self.config.retry_max_seconds,
                self.config.retry_base_seconds * (2**exponent),
            )
            delay *= self._random.uniform(0.8, 1.2)
            job.state = ScanJobState.RETRYING
            job.available_at = now + timedelta(seconds=delay)
            job.finished_at = None
        else:
            job.state = ScanJobState.FAILED
            job.available_at = None
            job.finished_at = now

    async def _execute(self, job: ScanJob, control: ExecutionControl) -> ScanResult:
        stored = await asyncio.to_thread(self.artifacts.load, job.job_id)
        stored_artifact = stored[1] if stored is not None else None
        await self._refresh_cancellation(job.job_id, control)

        target: ScanTarget | None = None
        if job.capability == ScanCapability.GUARD and (
            control.cancel_requested.is_set()
            or (
                isinstance(stored_artifact, ScanResult)
                and stored_artifact.kind == ScanCapability.GUARD
            )
        ):
            target_record = await asyncio.to_thread(
                self.state.scan_target_store.find_one, "target_id", job.target_id
            )
            if target_record is None:
                raise GuardReconciliationRequired(
                    f"scan target {job.target_id} no longer exists for Guard reconciliation"
                )
            target = ScanTarget.model_validate(target_record)
            identity_service = getattr(self.state, "agent_identity_service", None)
            unresolved = False
            if identity_service is None and isinstance(stored_artifact, ScanResult):
                # Legacy token deployments have no certificate generation. Join
                # the durable result to an identity-less manifest and the exact
                # live PID before allowing a conditional teardown.
                await self._bind_legacy_guard_deployment(target, stored_artifact, control)
            else:
                recovered, unresolved = await self._reconcile_guard_deployment(
                    job,
                    target,
                    control,
                    include_current_attempt=True,
                    activate_staged=not control.cancel_requested.is_set(),
                    allow_revoked=control.cancel_requested.is_set(),
                )
                if stored is not None and recovered is not None:
                    stored = (stored[0], recovered)
                    stored_artifact = recovered
                elif stored is not None and (unresolved or recovered is None):
                    raise GuardReconciliationRequired(
                        "durable Guard artifact is not backed by the live deployment manifest"
                    )

            if control.cancel_requested.is_set():
                if control.guard_side_effect_committed:
                    cleanup_error = await self._compensate_guard_if_needed(job, control)
                    if cleanup_error is not None:
                        raise GuardReconciliationRequired(cleanup_error)
                elif unresolved:
                    raise GuardReconciliationRequired(
                        "cancelled Guard generation has no matching live deployment manifest"
                    )
                raise ScanExecutionInterrupted("Guard cancellation was compensated")

        if control.interrupted:
            raise ScanExecutionInterrupted("scan interrupted before execution")

        if stored is None:
            if job.attempt > job.max_attempts and job.capability != ScanCapability.GUARD:
                raise ValueError(
                    "final scan attempt expired without a durable artifact; refusing to "
                    "repeat remote collection during reconciliation"
                )
            if target is None:
                target_record = await asyncio.to_thread(
                    self.state.scan_target_store.find_one, "target_id", job.target_id
                )
                if target_record is None:
                    raise ValueError(f"scan target {job.target_id} no longer exists")
                target = ScanTarget.model_validate(target_record)
            stored = await self._collect_and_spool(job, target, control)

        _, artifact = stored
        # A remote collection may have been blocking while an operator
        # cancelled the durable head (possibly through another Form replica).
        # Re-read that head before the irreversible Analyzer hand-off instead
        # of relying only on the next heartbeat tick.
        await self._refresh_cancellation(job.job_id, control)
        if control.interrupted:
            if control.cancel_requested.is_set() and control.guard_side_effect_committed:
                cleanup_error = await self._compensate_guard_if_needed(job, control)
                if cleanup_error is not None:
                    raise GuardReconciliationRequired(cleanup_error)
                raise ScanExecutionInterrupted("Guard cancellation was compensated")
            guard_completed = (
                isinstance(artifact, ScanResult)
                and artifact.kind == ScanCapability.GUARD
                and not control.cancel_requested.is_set()
                and not control.lease_lost.is_set()
            )
            if not guard_completed:
                raise ScanExecutionInterrupted("scan interrupted before Analyzer forwarding")
        if isinstance(artifact, AssetReport):
            await self.state.analyzer_client.ingest_asset_report(artifact)
            return ScanResult(
                kind=ScanCapability.HOST,
                report_id=artifact.report_id,
                host_id=artifact.host.host_id,
            )
        if isinstance(artifact, TraceBatch):
            await self.state.analyzer_client.ingest_trace_batch(artifact)
            return ScanResult(kind=ScanCapability.TRACE, batch_id=artifact.batch_id)
        if isinstance(artifact, ScanResult):
            return artifact
        raise TypeError(f"unsupported durable scan artifact: {type(artifact).__name__}")

    async def _refresh_cancellation(self, job_id: str, control: ExecutionControl) -> None:
        latest = await asyncio.to_thread(self.repository.get, job_id)
        if latest is not None and latest.state in {
            ScanJobState.CANCELLING,
            ScanJobState.CANCELLED,
        }:
            control.cancel_requested.set()

    async def _collect_and_spool(
        self,
        job: ScanJob,
        target: ScanTarget,
        control: ExecutionControl,
    ) -> tuple[Any, AssetReport | TraceBatch | ScanResult]:
        is_local = target.transport == Transport.LOCAL
        is_winrm = target.transport == Transport.WINRM
        if (is_local or is_winrm) and job.capability != ScanCapability.HOST:
            raise ValueError(
                f"capability {job.capability.value} is not supported for "
                f"{target.transport.value} targets"
            )

        if job.capability == ScanCapability.HOST:
            if is_local:
                artifact: AssetReport | TraceBatch | ScanResult = await asyncio.to_thread(
                    deploy_trigger.run_host_local,
                    job.options,
                    self.config.job_timeout_seconds,
                )
            elif is_winrm:
                artifact = await asyncio.to_thread(
                    deploy_trigger.run_host_winrm,
                    target,
                    job.options,
                )
            else:
                artifact = await asyncio.to_thread(deploy_trigger.run_host, target, job.options)
            kind = "asset-report"
        elif job.capability == ScanCapability.TRACE:
            artifact = await asyncio.to_thread(deploy_trigger.run_trace, target, job.options)
            kind = "trace-batch"
        else:
            identity_service = getattr(self.state, "agent_identity_service", None)
            public_url = self.public_url_resolver(identity_service is not None)
            if identity_service is not None:
                await asyncio.to_thread(
                    identity_service.ensure_identity,
                    target.target_id,
                    target.canonical_host_id or target.target_id,
                    [AgentScope.GUARD_EVENT],
                )

                # A prior owner may have committed remotely immediately before
                # losing its response/lease. Only the validated manifest joined
                # to this job's idempotent certificate and the exact live PID is
                # accepted as proof; an arbitrary alive Guard is never reused.
                artifact, unresolved = await self._reconcile_guard_deployment(
                    job,
                    target,
                    control,
                    include_current_attempt=False,
                    activate_staged=True,
                    allow_revoked=job.attempt > job.max_attempts,
                )
                if unresolved:
                    raise GuardReconciliationRequired(
                        "prior Guard certificate generation does not match the live manifest"
                    )
                if artifact is not None and control.guard_cleanup_pending:
                    cleanup_error = await self._compensate_guard_if_needed(job, control)
                    if cleanup_error is not None:
                        raise GuardReconciliationRequired(
                            "revoked Guard generation still requires conditional teardown: "
                            f"{cleanup_error}"
                        )
                    raise ValueError(
                        "final Guard artifact failed after remote commit; its revoked "
                        "generation was conditionally torn down during reconciliation"
                    )

                if artifact is None:
                    if job.attempt > job.max_attempts:
                        raise ValueError(
                            "final Guard attempt expired and its remote deployment could not "
                            "be reconciled; refusing to create an unfenced extra generation"
                        )
                    staged = await asyncio.to_thread(
                        identity_service.stage_for_target,
                        target.target_id,
                        target.canonical_host_id or target.target_id,
                        [AgentScope.GUARD_EVENT],
                        idempotency_key=f"{job.job_id}:attempt:{job.attempt}",
                    )
                    if staged.bundle is None:
                        raise RuntimeError(
                            "Agent certificate deployment material was already consumed; "
                            "retry the fenced scan attempt"
                        )
                    try:

                        def activate_generation() -> None:
                            if control.interrupted:
                                raise ScanExecutionInterrupted(
                                    "scan interrupted before Agent certificate activation"
                                )
                            identity_service.activate(
                                staged.identity.agent_id,
                                staged.certificate.generation,
                            )

                        artifact = await asyncio.to_thread(
                            deploy_trigger.run_guard,
                            target,
                            public_url,
                            None,
                            staged.bundle,
                            activate_generation,
                        )
                        recovered, unresolved = await self._reconcile_guard_deployment(
                            job,
                            target,
                            control,
                            include_current_attempt=True,
                            activate_staged=False,
                        )
                        if recovered is None or unresolved:
                            raise GuardReconciliationRequired(
                                "new Guard deployment is not backed by its live manifest"
                            )
                    except deploy_trigger.GuardDeploymentUncertainError:
                        # The remote transaction could have committed and its
                        # manifest is the only safe arbiter. Preserve STAGED so
                        # the next fenced owner can join it by idempotency key.
                        raise
                    except BaseException:
                        with contextlib.suppress(BaseException):
                            await asyncio.to_thread(
                                identity_service.abort,
                                staged.identity.agent_id,
                                staged.certificate.generation,
                            )
                        raise
            else:
                if job.attempt > job.max_attempts:
                    raise ValueError(
                        "final legacy Guard attempt expired without a durable artifact; "
                        "refusing an unfenced redeployment"
                    )
                token = getattr(self.state, "ingest_token", None)
                if not token:
                    raise ValueError(
                        "Agent identity management and FORM_INGEST_TOKEN are unavailable "
                        "for guard deployment"
                    )
                artifact = await asyncio.to_thread(
                    deploy_trigger.run_guard,
                    target,
                    public_url,
                    token,
                )
                await self._bind_legacy_guard_deployment(target, artifact, control)
            kind = "scan-result"

        # The remote payload's hostname/address is descriptive input, not a
        # security identity.  Canonicalize every Form-orchestrated artifact to
        # the stable target id before it is durably spooled or reaches Analyzer.
        if isinstance(artifact, (AssetReport, TraceBatch)):
            artifact = bind_form_envelope(
                artifact,
                target_id=target.target_id,
                canonical_host_id=target.canonical_host_id or target.target_id,
            )
        elif isinstance(artifact, ScanResult) and artifact.kind == ScanCapability.GUARD:
            control.guard_side_effect_committed = True
            artifact = artifact.model_copy(
                update={"host_id": target.canonical_host_id or target.target_id}
            )

        if control.interrupted:
            if control.cancel_requested.is_set() and control.guard_side_effect_committed:
                cleanup_error = await self._compensate_guard_if_needed(job, control)
                if cleanup_error is not None:
                    raise GuardReconciliationRequired(cleanup_error)
                raise ScanExecutionInterrupted("Guard cancellation was compensated")
            guard_may_complete = (
                isinstance(artifact, ScanResult)
                and artifact.kind == ScanCapability.GUARD
                and not control.cancel_requested.is_set()
                and not control.lease_lost.is_set()
            )
            if not guard_may_complete:
                # Explicit cancellation is compensated once, after the worker
                # regains the event loop. Lease loss never lets the stale owner
                # mutate a target now owned by a newer fenced attempt.
                raise ScanExecutionInterrupted("scan interrupted after remote collection")
        try:
            metadata = await asyncio.to_thread(self.artifacts.save, job.job_id, kind, artifact)
        except BaseException as exc:
            if (
                job.capability == ScanCapability.GUARD
                and control.guard_side_effect_committed
                and job.attempt >= job.max_attempts
                and not control.lease_lost.is_set()
            ):
                cleanup_error = await self._compensate_guard_if_needed(job, control)
                if cleanup_error is not None:
                    raise GuardReconciliationRequired(
                        f"final Guard artifact failed and compensation is pending: {cleanup_error}"
                    ) from exc
            raise
        return metadata, artifact


def _retryable(error: BaseException) -> bool:
    if isinstance(error, AnalyzerUpstreamError):
        return error.status_code is None or error.status_code in _TRANSIENT_ANALYZER_STATUSES
    if isinstance(error, StorageCapacityError):
        return True
    if isinstance(error, (TimeoutError, ConnectionError, OSError)):
        return not isinstance(error, (FileNotFoundError, PermissionError))
    if isinstance(error, (ValueError, TypeError)):
        return False
    return isinstance(error, RuntimeError)


def _bounded_error(value: str) -> str:
    if len(value) <= 4_096:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    suffix = f"~sha256:{digest}"
    return f"{value[: 4_096 - len(suffix)]}{suffix}"
