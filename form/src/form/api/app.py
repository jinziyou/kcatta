"""FastAPI application factory."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..storage import JsonlStore
from . import ingest, reports

DEFAULT_DATA_DIR = Path("data")
DEFAULT_CORS_ORIGINS = "http://localhost:3000"


def _data_dir() -> Path:
    env = os.getenv("FORM_DATA_DIR")
    return Path(env) if env else DEFAULT_DATA_DIR


def _cors_origins() -> list[str]:
    raw = os.getenv("FORM_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def create_app(
    data_dir: Path | None = None,
    cors_origins: list[str] | None = None,
) -> FastAPI:
    """Build the FastAPI app and wire its dependencies.

    ``data_dir`` overrides the default, which itself can be set via the
    ``FORM_DATA_DIR`` environment variable. Tests use this to redirect
    persistence to a temporary directory.

    ``cors_origins`` overrides the default (the value of
    ``FORM_CORS_ORIGINS``, or ``http://localhost:3000`` if unset).
    """

    dir_ = data_dir if data_dir is not None else _data_dir()
    origins = cors_origins if cors_origins is not None else _cors_origins()

    app = FastAPI(
        title="cyber-posture form",
        version="0.1.0",
        description="Ingest, normalize, correlate, and serve security telemetry.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.state.asset_report_store = JsonlStore(dir_ / "asset-reports.jsonl")
    app.state.flow_batch_store = JsonlStore(dir_ / "flow-batches.jsonl")

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(ingest.router)
    app.include_router(reports.router)

    return app
