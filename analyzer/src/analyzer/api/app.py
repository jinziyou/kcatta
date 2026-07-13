"""FastAPI application factory."""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from ..detect import OsvStore
from ..logging_config import configure_logging
from ..storage import StorageCapacityError, create_store
from . import alerts, detect, ingest, predict, reports
from .auth import require_internal_token
from .idempotency import DEFAULT_WINDOW, SeenIds

logger = logging.getLogger("analyzer.api")

DEFAULT_DATA_DIR = Path("data")
DEFAULT_OSV_DIR = DEFAULT_DATA_DIR / "osv"
# Reject oversized ingest bodies (DoS guard); override via ANALYZER_MAX_BODY_BYTES.
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024


def _data_dir() -> Path:
    env = os.getenv("ANALYZER_DATA_DIR")
    return Path(env) if env else DEFAULT_DATA_DIR


def _osv_dir() -> Path:
    env = os.getenv("ANALYZER_OSV_DIR")
    return Path(env) if env else DEFAULT_OSV_DIR


def create_app(
    data_dir: Path | None = None,
    osv_dir: Path | None = None,
    osv_ecosystem: str | None = None,
    api_token: str | None = None,
    storage_backend: str | None = None,
    allow_insecure_no_auth: bool | None = None,
) -> FastAPI:
    """Build the FastAPI app and wire its dependencies.

    ``data_dir`` overrides the default, which itself can be set via the
    ``ANALYZER_DATA_DIR`` environment variable. Tests use this to redirect
    persistence to a temporary directory.

    ``osv_dir`` is the local OSV advisory store loaded once at startup for
    the ``/detect`` endpoint (env ``ANALYZER_OSV_DIR``, default ``data/osv``);
    a missing directory yields an empty store rather than an error.
    ``osv_ecosystem`` (env ``ANALYZER_OSV_ECOSYSTEM``) pins the OSV ecosystem
    instead of deriving it per report from ``host.os``.

    ``api_token`` is retained as a test/backward-compatible constructor
    argument. In deployments the internal Form-to-Analyzer bearer token comes
    from ``ANALYZER_INTERNAL_TOKEN`` and protects every route except ``/health``.
    Analyzer is an internal service; Admin and Agent authenticate to Form, not
    directly to this API. An unset token fails closed unless local development
    explicitly sets ``ANALYZER_ALLOW_INSECURE_NO_AUTH=true``.

    ``storage_backend`` (env ``ANALYZER_STORAGE``) selects ``jsonl`` (default) or
    ``sqlite`` persistence under ``data_dir``.
    """

    # E1: configure business-logger handlers up front so swallowed ingest errors
    # (detection/correlation failures) are actually emitted, not silently lost.
    configure_logging()

    dir_ = data_dir if data_dir is not None else _data_dir()
    osv_dir_ = osv_dir if osv_dir is not None else _osv_dir()
    ecosystem_ = osv_ecosystem if osv_ecosystem is not None else os.getenv("ANALYZER_OSV_ECOSYSTEM")
    token_ = api_token if api_token is not None else os.getenv("ANALYZER_INTERNAL_TOKEN") or ""
    token_ = token_.strip() or None
    allow_insecure = (
        allow_insecure_no_auth
        if allow_insecure_no_auth is not None
        else os.getenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    if not token_ and not allow_insecure:
        raise RuntimeError(
            "ANALYZER_INTERNAL_TOKEN is required; set "
            "ANALYZER_ALLOW_INSECURE_NO_AUTH=true only for isolated local development"
        )
    store_backend = storage_backend

    app = FastAPI(
        title="kcatta analyzer",
        version="0.1.0",
        description="Internal ingest, detection, correlation, and reporting service.",
    )

    @app.exception_handler(StorageCapacityError)
    async def _storage_capacity_exhausted(
        request: Request, exc: StorageCapacityError
    ) -> JSONResponse:
        logger.error(
            "storage capacity rejected request %s: %s",
            getattr(request.state, "request_id", "unknown"),
            exc,
        )
        return JSONResponse(
            status_code=507,
            headers={"Retry-After": "60"},
            content={"detail": "Analyzer durable storage capacity is exhausted"},
        )

    max_body_bytes = int(os.getenv("ANALYZER_MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES)))

    @app.middleware("http")
    async def _request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Attach a request id (honour an inbound X-Request-ID) so a log line can be
        # tied back to one request; echoed on the response for client correlation.
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

    @app.middleware("http")
    async def _limit_body_size(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Defense in depth behind Form: reject oversized forwarded payloads so a
        # malformed internal request cannot exhaust Analyzer memory/disk.
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                too_big = int(content_length) > max_body_bytes
            except ValueError:
                too_big = False
            if too_big:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"request body exceeds {max_body_bytes} bytes"},
                )
        return await call_next(request)

    app.state.asset_report_store = create_store(dir_, "asset_reports", backend=store_backend)
    app.state.trace_batch_store = create_store(dir_, "trace_batches", backend=store_backend)
    app.state.guard_event_store = create_store(dir_, "guard_events", backend=store_backend)
    app.state.vulnerability_store = create_store(dir_, "vulnerabilities", backend=store_backend)
    app.state.alert_store = create_store(dir_, "alerts", backend=store_backend)
    # Append-only triage overlay (status/assignee/note/suppress) keyed by alert_key.
    app.state.alert_state_store = create_store(dir_, "alert_states", backend=store_backend)
    app.state.capability_graph_store = create_store(
        dir_, "capability_graphs", backend=store_backend
    )
    app.state.osv_store = OsvStore.load_dir(osv_dir_)
    if app.state.osv_store.record_count == 0:
        # An empty OSV store makes vulnerability detection silently no-op
        # (detect/ingest gate on record_count > 0) — for a blue-team tool that
        # reads as "no vulnerabilities" when the truth is "not inspected". Surface
        # it loudly at startup so an operator knows to run `analyzer-osv-sync`.
        logger.warning(
            "OSV store at %s is empty — vulnerability detection is DISABLED until "
            "you populate it (run `analyzer-osv-sync`). Scanner/malware findings "
            "still flow; only OSV CVE/GHSA matching is off.",
            osv_dir_,
        )
    app.state.osv_ecosystem = ecosystem_
    app.state.internal_token = token_
    # Idempotency guard: drop duplicate Form forwards/retries by envelope id so
    # a retried-but-already-processed upload doesn't land a second row.
    dedup_window = int(os.getenv("ANALYZER_INGEST_DEDUP_WINDOW", str(DEFAULT_WINDOW)))
    app.state.ingest_seen = SeenIds(maxlen=dedup_window)

    internal_auth = [Depends(require_internal_token)]

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        """Liveness probe returning a static ok status."""
        return {"status": "ok"}

    app.include_router(ingest.router, dependencies=internal_auth)
    app.include_router(reports.router, dependencies=internal_auth)
    app.include_router(alerts.router, dependencies=internal_auth)
    app.include_router(detect.router, dependencies=internal_auth)
    app.include_router(predict.router, dependencies=internal_auth)

    return app
