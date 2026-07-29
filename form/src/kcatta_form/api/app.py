"""FastAPI application factory for the Form control plane."""

from __future__ import annotations

import asyncio
import logging
import math
import os
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .. import metrics as metrics_mod
from ..agent_runtime import (
    agent_identity_enabled,
    load_or_create_agent_identity_service,
    maintain_agent_server_certificate,
)
from ..analyzer_client import AnalyzerClient
from ..derived_reconciler import DerivedStatusReconciler
from ..job_store import ScanJobRepository
from ..mde import MdeConfig, MdeSyncWorker
from ..mdvm import MdvmConfig, MdvmSyncWorker
from ..scan_artifacts import ScanArtifactStore
from ..scan_worker import ScanJobWorker, ScanWorkerConfig
from ..schedule_store import ScheduleStore
from ..schedule_worker import ScheduleWorker
from ..storage import create_form_store, latest_legacy_scan_jobs
from . import agent_identities, credentials, scans, schedules
from .auth import require_api_token, require_metrics_token
from .middleware import BodySizeLimitMiddleware
from .proxy import ingest_router, knowledge_router, query_router

logger = logging.getLogger("kcatta_form.api")

DEFAULT_DATA_DIR = Path("data")
DEFAULT_ANALYZER_URL = "http://127.0.0.1:10068"
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_IN_FLIGHT = 16
DEFAULT_MAX_IN_FLIGHT_PER_PEER = 8
DEFAULT_MAX_INGEST_IN_FLIGHT_PER_PEER = 4
DEFAULT_INGEST_RATE_PER_SECOND = 5.0
DEFAULT_INGEST_BURST = 20
DEFAULT_BODY_READ_TIMEOUT_SECONDS = 30.0


def _data_dir() -> Path:
    configured = os.getenv("FORM_DATA_DIR")
    return Path(configured) if configured else DEFAULT_DATA_DIR


def _timeout() -> float:
    raw = os.getenv("FORM_ANALYZER_TIMEOUT_SECONDS", "30")
    try:
        return max(1.0, float(raw))
    except ValueError:
        return 30.0


def _max_body_bytes() -> int:
    raw = os.getenv("FORM_MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES))
    try:
        value = int(raw)
    except ValueError:
        logger.warning("invalid FORM_MAX_BODY_BYTES=%r; using %d", raw, DEFAULT_MAX_BODY_BYTES)
        return DEFAULT_MAX_BODY_BYTES
    if not math.isfinite(value) or value <= 0:
        logger.warning("non-positive FORM_MAX_BODY_BYTES=%r; using %d", raw, DEFAULT_MAX_BODY_BYTES)
        return DEFAULT_MAX_BODY_BYTES
    return value


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        logger.warning("invalid %s=%r; using %d", name, raw, default)
        return default
    if value <= 0:
        logger.warning("non-positive %s=%r; using %d", name, raw, default)
        return default
    return value


def _positive_float_env(name: str, default: float) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError:
        logger.warning("invalid %s=%r; using %s", name, raw, default)
        return default
    if not math.isfinite(value) or value <= 0:
        logger.warning("non-positive %s=%r; using %s", name, raw, default)
        return default
    return value


def create_app(
    data_dir: Path | None = None,
    *,
    api_token: str | None = None,
    ingest_token: str | None = None,
    metrics_token: str | None = None,
    analyzer_url: str | None = None,
    analyzer_token: str | None = None,
    storage_backend: str | None = None,
    analyzer_client: AnalyzerClient | None = None,
    allow_insecure_no_auth: bool | None = None,
    agent_auth_mode: str | None = None,
) -> FastAPI:
    """Create Form with explicit dependency overrides for tests and embedding."""
    dir_ = data_dir if data_dir is not None else _data_dir()
    api_token_ = (api_token if api_token is not None else os.getenv("FORM_API_TOKEN") or "").strip()
    ingest_token_ = (
        ingest_token if ingest_token is not None else os.getenv("FORM_INGEST_TOKEN") or ""
    ).strip()
    metrics_token_ = (
        metrics_token if metrics_token is not None else os.getenv("FORM_METRICS_TOKEN") or ""
    ).strip()
    agent_auth_mode_ = (
        (agent_auth_mode or os.getenv("FORM_AGENT_AUTH_MODE", "legacy")).strip().lower()
    )
    if agent_auth_mode_ not in {"legacy", "mixed", "mtls"}:
        raise RuntimeError("FORM_AGENT_AUTH_MODE must be legacy, mixed, or mtls")
    if agent_auth_mode_ in {"legacy", "mixed"} and bool(api_token_) != bool(ingest_token_):
        raise RuntimeError(
            "FORM_API_TOKEN and FORM_INGEST_TOKEN must either both be configured "
            f"or both be absent in {agent_auth_mode_} Agent auth mode"
        )
    if api_token_ and secrets.compare_digest(api_token_, ingest_token_):
        raise RuntimeError("FORM_API_TOKEN and FORM_INGEST_TOKEN must be distinct")
    if metrics_token_ and any(
        token and secrets.compare_digest(metrics_token_, token)
        for token in (api_token_, ingest_token_)
    ):
        raise RuntimeError(
            "FORM_METRICS_TOKEN must be distinct from Form control and ingest tokens"
        )
    allow_insecure = (
        allow_insecure_no_auth
        if allow_insecure_no_auth is not None
        else os.getenv("FORM_ALLOW_INSECURE_NO_AUTH", "").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    if not api_token_ and not allow_insecure:
        if agent_auth_mode_ in {"legacy", "mixed"}:
            raise RuntimeError(
                "FORM_API_TOKEN and FORM_INGEST_TOKEN are required; set "
                "FORM_ALLOW_INSECURE_NO_AUTH=true only for isolated local development"
            )
        raise RuntimeError(
            "FORM_API_TOKEN is required in mTLS Agent auth mode; set "
            "FORM_ALLOW_INSECURE_NO_AUTH=true only for isolated local development"
        )
    api_token_ = api_token_ or None
    ingest_token_ = ingest_token_ or None
    metrics_token_ = metrics_token_ or api_token_
    analyzer_url_ = analyzer_url or os.getenv("FORM_ANALYZER_BASE_URL", DEFAULT_ANALYZER_URL)
    analyzer_token_ = (
        analyzer_token if analyzer_token is not None else os.getenv("ANALYZER_INTERNAL_TOKEN") or ""
    ).strip() or None
    if analyzer_client is None and api_token_ and not analyzer_token_:
        raise RuntimeError(
            "ANALYZER_INTERNAL_TOKEN is required when Form authentication is enabled"
        )
    if analyzer_token_ and any(
        token and secrets.compare_digest(analyzer_token_, token)
        for token in (api_token_, ingest_token_, metrics_token_)
    ):
        raise RuntimeError(
            "ANALYZER_INTERNAL_TOKEN must be distinct from Form control, ingest, and metrics tokens"
        )
    backend_ = storage_backend or os.getenv("FORM_STORAGE", "jsonl")
    client = analyzer_client or AnalyzerClient(analyzer_url_, analyzer_token_, timeout=_timeout())
    target_store = create_form_store(dir_, "scan_targets", backend=backend_)
    legacy_job_store = create_form_store(dir_, "scan_jobs", backend=backend_)
    job_repository = ScanJobRepository(dir_)
    try:
        job_repository.import_legacy(latest_legacy_scan_jobs(legacy_job_store), datetime.now(UTC))
    finally:
        close_legacy = getattr(legacy_job_store, "close", None)
        if callable(close_legacy):
            close_legacy()
    artifact_store = ScanArtifactStore(dir_ / "scan-artifacts")
    removed_artifacts = artifact_store.reconcile(job_repository.retains_artifact)
    if removed_artifacts:
        logger.info("removed %d stale scan spool artifact(s)", removed_artifacts)
    worker_config = ScanWorkerConfig.from_env()
    agent_identity_service = None
    agent_runtime_paths = None
    if agent_identity_enabled(agent_auth_mode_):
        agent_identity_service, agent_runtime_paths = load_or_create_agent_identity_service(dir_)

    schedule_store = ScheduleStore(dir_)
    mde_config = MdeConfig.from_env(dir_)
    mdvm_config = MdvmConfig.from_env(dir_)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await app.state.derived_reconciler.start()
        await app.state.scan_worker.start()
        await app.state.schedule_worker.start()
        await app.state.mde_sync_worker.start()
        await app.state.mdvm_sync_worker.start()
        certificate_task = None
        if app.state.agent_identity_service is not None:
            certificate_task = asyncio.create_task(
                maintain_agent_server_certificate(
                    app.state.agent_identity_service,
                    app.state.agent_runtime_paths,
                ),
                name="form-agent-server-certificate-maintenance",
            )
        app.state.agent_server_certificate_task = certificate_task
        try:
            yield
        finally:
            if certificate_task is not None:
                certificate_task.cancel()
                with suppress(asyncio.CancelledError):
                    await certificate_task
            # Stop claiming and wait for real executions before closing their
            # Analyzer client/repositories. Forced shutdown leaves a valid lease
            # for expiry recovery rather than fabricating a FAILED state.
            await app.state.mdvm_sync_worker.stop()
            await app.state.mde_sync_worker.stop()
            await app.state.schedule_worker.stop()
            await app.state.scan_worker.stop()
            await app.state.derived_reconciler.stop()
            await app.state.analyzer_client.close()
            for name in ("scan_target_store", "scan_job_repository", "schedule_store"):
                close = getattr(getattr(app.state, name, None), "close", None)
                if callable(close):
                    close()
            if app.state.agent_identity_service is not None:
                app.state.agent_identity_service.repository.close()

    app = FastAPI(
        title="kcatta Form",
        version="0.1.0",
        description=(
            "Control plane and the only integration boundary for admin, analyzer, and agent."
        ),
        lifespan=lifespan,
    )
    app.state.api_token = api_token_
    app.state.ingest_token = ingest_token_
    app.state.metrics_token = metrics_token_
    app.state.agent_auth_mode = agent_auth_mode_
    app.state.agent_identity_service = agent_identity_service
    app.state.agent_runtime_paths = agent_runtime_paths
    app.state.analyzer_client = client
    app.state.scan_target_store = target_store
    app.state.scan_job_repository = job_repository
    # Read-only compatibility alias for callers/tests that have not yet renamed
    # their app-state lookup. Runtime transitions use repository CAS methods.
    app.state.scan_job_store = job_repository
    app.state.scan_artifact_store = artifact_store
    app.state.schedule_store = schedule_store
    app.state.scan_worker = ScanJobWorker(
        app.state,
        job_repository,
        artifact_store,
        public_url_resolver=scans._public_url,
        config=worker_config,
    )
    app.state.derived_reconciler = DerivedStatusReconciler(client, job_repository)
    app.state.schedule_worker = ScheduleWorker(
        app.state,
        schedule_store,
        job_repository,
        poll_seconds=float(os.getenv("FORM_SCHEDULE_POLL_SECONDS", "15")),
    )
    app.state.mde_sync_worker = MdeSyncWorker(mde_config, client)
    app.state.mdvm_sync_worker = MdvmSyncWorker(mdvm_config, client)

    max_body_bytes = _max_body_bytes()

    @app.middleware("http")
    async def request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

    app.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=max_body_bytes,
        control_token=api_token_,
        ingest_token=ingest_token_,
        metrics_token=metrics_token_,
        max_in_flight=_positive_int_env("FORM_MAX_IN_FLIGHT", DEFAULT_MAX_IN_FLIGHT),
        max_in_flight_per_peer=_positive_int_env(
            "FORM_MAX_IN_FLIGHT_PER_PEER", DEFAULT_MAX_IN_FLIGHT_PER_PEER
        ),
        max_ingest_in_flight_per_peer=_positive_int_env(
            "FORM_MAX_INGEST_IN_FLIGHT_PER_PEER", DEFAULT_MAX_INGEST_IN_FLIGHT_PER_PEER
        ),
        ingest_rate_per_second=_positive_float_env(
            "FORM_INGEST_RATE_PER_SECOND", DEFAULT_INGEST_RATE_PER_SECOND
        ),
        ingest_burst=_positive_int_env("FORM_INGEST_BURST", DEFAULT_INGEST_BURST),
        body_read_timeout_seconds=_positive_float_env(
            "FORM_BODY_READ_TIMEOUT_SECONDS", DEFAULT_BODY_READ_TIMEOUT_SECONDS
        ),
        agent_auth_mode=agent_auth_mode_,
    )

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready", tags=["meta"], dependencies=[Depends(require_api_token)])
    async def ready() -> JSONResponse:
        # Probe an authenticated Analyzer route rather than its public liveness
        # endpoint, so a mismatched internal token cannot report a false ready.
        analyzer_ready = await app.state.analyzer_client.ready()
        worker_ready = app.state.scan_worker.healthy
        schedule_ready = app.state.schedule_worker.healthy
        reconciler_ready = app.state.derived_reconciler.healthy
        mde_detail = app.state.mde_sync_worker.readiness()
        mde_status = str(mde_detail.get("mde") or "unknown")
        mdvm_detail = app.state.mdvm_sync_worker.readiness()
        mdvm_status = str(mdvm_detail.get("mdvm") or "unknown")
        analyzer_detail = await app.state.analyzer_client.readiness_detail()
        osv_status = str(analyzer_detail.get("osv") or "unknown")
        tracker_status = str(analyzer_detail.get("debian_tracker") or "unknown")
        # Incomplete advisory coverage is degraded, not Form unready: keep HTTP
        # 200 so orchestrators do not crash-loop a serviceable stack. Unknown
        # values also degrade mixed-version deployments instead of claiming
        # coverage that an older/unreachable readiness endpoint did not prove.
        core_ready = analyzer_ready and worker_ready and schedule_ready and reconciler_ready
        osv_empty = osv_status == "empty"
        tracker_empty = tracker_status == "empty"
        tracker_stale = tracker_status == "stale"
        osv_degraded = osv_status != "ready"
        tracker_degraded = tracker_status != "ready"
        if not core_ready:
            status_code = 503
            status_label = "degraded"
        elif (
            osv_degraded
            or tracker_degraded
            or mde_status in {"degraded", "starting", "unknown"}
            or mdvm_status in {"degraded", "starting", "unknown"}
        ):
            status_code = 200
            status_label = "degraded"
        else:
            status_code = 200
            status_label = "ready"
        metrics_mod.set_gauge("kcatta_form_ready", 1.0 if core_ready else 0.0)
        metrics_mod.set_gauge("kcatta_form_osv_empty", 1.0 if osv_empty else 0.0)
        metrics_mod.set_gauge("kcatta_form_osv_degraded", 1.0 if osv_degraded else 0.0)
        metrics_mod.set_gauge("kcatta_form_debian_tracker_empty", 1.0 if tracker_empty else 0.0)
        metrics_mod.set_gauge("kcatta_form_debian_tracker_stale", 1.0 if tracker_stale else 0.0)
        metrics_mod.set_gauge(
            "kcatta_form_debian_tracker_degraded",
            1.0 if tracker_degraded else 0.0,
        )
        metrics_mod.set_gauge(
            "kcatta_form_mde_degraded",
            1.0 if mde_status in {"degraded", "starting", "unknown"} else 0.0,
        )
        metrics_mod.set_gauge(
            "kcatta_form_mdvm_degraded",
            1.0 if mdvm_status in {"degraded", "starting", "unknown"} else 0.0,
        )
        return JSONResponse(
            status_code=status_code,
            content={
                "status": status_label,
                "analyzer": "ready" if analyzer_ready else "unavailable",
                "worker": "ready" if worker_ready else "unavailable",
                "scheduler": "ready" if schedule_ready else "unavailable",
                "derived_reconciler": "ready" if reconciler_ready else "unavailable",
                **mde_detail,
                **mdvm_detail,
                "osv": osv_status,
                "osv_record_count": analyzer_detail.get("osv_record_count"),
                "debian_tracker": tracker_status,
                "debian_tracker_record_count": analyzer_detail.get("debian_tracker_record_count"),
                "debian_tracker_source_package_count": analyzer_detail.get(
                    "debian_tracker_source_package_count"
                ),
                "debian_tracker_synced_at": analyzer_detail.get("debian_tracker_synced_at"),
                "debian_tracker_age_seconds": analyzer_detail.get("debian_tracker_age_seconds"),
                "debian_tracker_max_age_seconds": analyzer_detail.get(
                    "debian_tracker_max_age_seconds"
                ),
                "debian_tracker_auto_sync": analyzer_detail.get("debian_tracker_auto_sync"),
                "debian_tracker_refresh_seconds": analyzer_detail.get(
                    "debian_tracker_refresh_seconds"
                ),
            },
        )

    @app.get(
        "/metrics",
        tags=["meta"],
        response_class=PlainTextResponse,
        dependencies=[Depends(require_metrics_token)],
    )
    async def metrics() -> PlainTextResponse:
        with suppress(Exception):
            metrics_mod.set_gauge(
                "kcatta_form_active_scans",
                float(app.state.scan_worker.active_count),
            )
        return PlainTextResponse(
            metrics_mod.render_prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    control_auth = [Depends(require_api_token)]
    app.include_router(scans.router, dependencies=control_auth)
    app.include_router(schedules.router, dependencies=control_auth)
    app.include_router(credentials.router, dependencies=control_auth)
    app.include_router(agent_identities.router, dependencies=control_auth)
    app.include_router(query_router)
    app.include_router(ingest_router)
    app.include_router(knowledge_router)
    return app
