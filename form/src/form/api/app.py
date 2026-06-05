"""FastAPI application factory."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..detect import OsvStore
from ..storage import create_store
from . import detect, ingest, predict, reports
from .auth import require_api_token

DEFAULT_DATA_DIR = Path("data")
DEFAULT_OSV_DIR = DEFAULT_DATA_DIR / "osv"
DEFAULT_CORS_ORIGINS = "http://localhost:3000"


def _data_dir() -> Path:
    env = os.getenv("FORM_DATA_DIR")
    return Path(env) if env else DEFAULT_DATA_DIR


def _osv_dir() -> Path:
    env = os.getenv("FORM_OSV_DIR")
    return Path(env) if env else DEFAULT_OSV_DIR


def _cors_origins() -> list[str]:
    raw = os.getenv("FORM_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
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
    ``FORM_DATA_DIR`` environment variable. Tests use this to redirect
    persistence to a temporary directory.

    ``cors_origins`` overrides the default (the value of
    ``FORM_CORS_ORIGINS``, or ``http://localhost:3000`` if unset).

    ``osv_dir`` is the local OSV advisory store loaded once at startup for
    the ``/detect`` endpoint (env ``FORM_OSV_DIR``, default ``data/osv``);
    a missing directory yields an empty store rather than an error.
    ``osv_ecosystem`` (env ``FORM_OSV_ECOSYSTEM``) pins the OSV ecosystem
    instead of deriving it per report from ``host.os``.

    ``api_token`` (env ``FORM_API_TOKEN``) enables bearer auth on ingest,
    reports, and detect routes. When unset, the API stays open (v0 dev default).

    ``storage_backend`` (env ``FORM_STORAGE``) selects ``jsonl`` (default) or
    ``sqlite`` persistence under ``data_dir``.
    """

    dir_ = data_dir if data_dir is not None else _data_dir()
    origins = cors_origins if cors_origins is not None else _cors_origins()
    osv_dir_ = osv_dir if osv_dir is not None else _osv_dir()
    ecosystem_ = osv_ecosystem if osv_ecosystem is not None else os.getenv("FORM_OSV_ECOSYSTEM")
    token_ = api_token if api_token is not None else os.getenv("FORM_API_TOKEN")
    store_backend = storage_backend

    app = FastAPI(
        title="posture form",
        version="0.1.0",
        description="Ingest, normalize, correlate, and serve security telemetry.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.state.asset_report_store = create_store(dir_, "asset_reports", backend=store_backend)
    app.state.flow_batch_store = create_store(dir_, "flow_batches", backend=store_backend)
    app.state.vulnerability_store = create_store(dir_, "vulnerabilities", backend=store_backend)
    app.state.alert_store = create_store(dir_, "alerts", backend=store_backend)
    app.state.capability_graph_store = create_store(
        dir_, "capability_graphs", backend=store_backend
    )
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

    return app
