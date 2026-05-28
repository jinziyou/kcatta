"""FastAPI application factory."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI

from ..storage import JsonlStore
from . import ingest

DEFAULT_DATA_DIR = Path("data")


def _data_dir() -> Path:
    env = os.getenv("FORM_DATA_DIR")
    return Path(env) if env else DEFAULT_DATA_DIR


def create_app(data_dir: Path | None = None) -> FastAPI:
    """Build the FastAPI app and wire its dependencies.

    `data_dir` overrides the default, which itself can be set via the
    ``FORM_DATA_DIR`` environment variable. Tests use this to redirect
    persistence to a temporary directory.
    """

    dir_ = data_dir if data_dir is not None else _data_dir()

    app = FastAPI(
        title="cyber-posture form",
        version="0.1.0",
        description="Ingest, normalize, correlate, and serve security telemetry.",
    )

    app.state.asset_report_store = JsonlStore(dir_ / "asset-reports.jsonl")
    app.state.flow_batch_store = JsonlStore(dir_ / "flow-batches.jsonl")

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(ingest.router)

    return app
