"""FastAPI application factory."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..detect import OsvStore
from ..storage import create_store
from . import detect, ingest, predict, reports, scans
from .auth import require_api_token

DEFAULT_DATA_DIR = Path("data")
DEFAULT_OSV_DIR = DEFAULT_DATA_DIR / "osv"
DEFAULT_CORS_ORIGINS = "http://localhost:3000"
# Reject oversized ingest bodies (DoS guard); override via FUSION_MAX_BODY_BYTES.
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024


def _data_dir() -> Path:
    env = os.getenv("FUSION_DATA_DIR")
    return Path(env) if env else DEFAULT_DATA_DIR


def _osv_dir() -> Path:
    env = os.getenv("FUSION_OSV_DIR")
    return Path(env) if env else DEFAULT_OSV_DIR


def _cors_origins() -> list[str]:
    raw = os.getenv("FUSION_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def create_app(
    data_dir: Path | None = None,
    cors_origins: list[str] | None = None,
    osv_dir: Path | None = None,
    osv_ecosystem: str | None = None,
    api_token: str | None = None,
    storage_backend: str | None = None,
) -> FastAPI:
    """Build the FastAPI app and wire its dependencies.

    ``data_dir`` overrides the default, which itself can be set via the
    ``FUSION_DATA_DIR`` environment variable. Tests use this to redirect
    persistence to a temporary directory.

    ``cors_origins`` overrides the default (the value of
    ``FUSION_CORS_ORIGINS``, or ``http://localhost:3000`` if unset).

    ``osv_dir`` is the local OSV advisory store loaded once at startup for
    the ``/detect`` endpoint (env ``FUSION_OSV_DIR``, default ``data/osv``);
    a missing directory yields an empty store rather than an error.
    ``osv_ecosystem`` (env ``FUSION_OSV_ECOSYSTEM``) pins the OSV ecosystem
    instead of deriving it per report from ``host.os``.

    ``api_token`` (env ``FUSION_API_TOKEN``) enables bearer auth on ingest,
    reports, detect, attack-path, and target/scan routes (everything except
    ``/health``). When unset, the API stays open (v0 dev default).

    ``storage_backend`` (env ``FUSION_STORAGE``) selects ``jsonl`` (default) or
    ``sqlite`` persistence under ``data_dir``.
    """

    dir_ = data_dir if data_dir is not None else _data_dir()
    origins = cors_origins if cors_origins is not None else _cors_origins()
    osv_dir_ = osv_dir if osv_dir is not None else _osv_dir()
    ecosystem_ = osv_ecosystem if osv_ecosystem is not None else os.getenv("FUSION_OSV_ECOSYSTEM")
    token_ = api_token if api_token is not None else os.getenv("FUSION_API_TOKEN")
    store_backend = storage_backend

    app = FastAPI(
        title="posture fusion",
        version="0.1.0",
        description="Ingest, normalize, correlate, and serve security telemetry.",
    )

    max_body_bytes = int(os.getenv("FUSION_MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES)))

    @app.middleware("http")
    async def _limit_body_size(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Reject oversized payloads up front (auth may be off in dev) so a huge
        # ingest can't exhaust memory/disk. Relies on Content-Length, which the
        # agent's HTTP client and curl both send.
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

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST"],
        # Explicit header whitelist (the portal only sends these) rather than
        # "*", and credentials off by design — auth rides the Authorization
        # bearer header, never cookies.
        allow_headers=["Authorization", "Content-Type"],
        allow_credentials=False,
    )

    app.state.asset_report_store = create_store(dir_, "asset_reports", backend=store_backend)
    app.state.flow_batch_store = create_store(dir_, "flow_batches", backend=store_backend)
    app.state.guard_event_store = create_store(dir_, "guard_events", backend=store_backend)
    app.state.vulnerability_store = create_store(dir_, "vulnerabilities", backend=store_backend)
    app.state.alert_store = create_store(dir_, "alerts", backend=store_backend)
    app.state.capability_graph_store = create_store(
        dir_, "capability_graphs", backend=store_backend
    )
    # Scan orchestration: target registry + async scan-job tracking (portal trigger).
    app.state.scan_target_store = create_store(dir_, "scan_targets", backend=store_backend)
    app.state.scan_job_store = create_store(dir_, "scan_jobs", backend=store_backend)
    app.state.osv_store = OsvStore.load_dir(osv_dir_)
    app.state.osv_ecosystem = ecosystem_
    app.state.api_token = token_

    auth = [Depends(require_api_token)]

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        """Liveness probe returning a static ok status."""
        return {"status": "ok"}

    app.include_router(ingest.router, dependencies=auth)
    app.include_router(reports.router, dependencies=auth)
    app.include_router(detect.router, dependencies=auth)
    app.include_router(predict.router, dependencies=auth)
    app.include_router(scans.router, dependencies=auth)

    return app
