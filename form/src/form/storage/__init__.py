"""Persistence backends used by form's ingest pipeline."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from .jsonl import JsonlStore
from .migrate import migrate_jsonl_to_sqlite
from .sqlite import (
    TABLE_ALERTS,
    TABLE_ASSET_REPORTS,
    TABLE_CAPABILITY_GRAPHS,
    TABLE_FLOW_BATCHES,
    TABLE_VULNERABILITIES,
    SqliteStore,
)

StoreKind = Literal[
    "asset_reports",
    "flow_batches",
    "vulnerabilities",
    "alerts",
    "capability_graphs",
]

_JSONL_FILES: dict[StoreKind, str] = {
    "asset_reports": "asset-reports.jsonl",
    "flow_batches": "flow-batches.jsonl",
    "vulnerabilities": "vulnerabilities.jsonl",
    "alerts": "alerts.jsonl",
    "capability_graphs": "capability-graphs.jsonl",
}

_SQLITE_TABLES: dict[StoreKind, str] = {
    "asset_reports": TABLE_ASSET_REPORTS,
    "flow_batches": TABLE_FLOW_BATCHES,
    "vulnerabilities": TABLE_VULNERABILITIES,
    "alerts": TABLE_ALERTS,
    "capability_graphs": TABLE_CAPABILITY_GRAPHS,
}


class RecordStore:
    """Common surface for JsonlStore and SqliteStore."""

    def append(self, record: BaseModel) -> None:
        """Persist one record to the backing store."""
        raise NotImplementedError

    def tail(self, limit: int) -> list[dict]:
        """Return up to ``limit`` most recent records, newest first."""
        raise NotImplementedError

    def find_one(self, field: str, value: str) -> dict | None:
        """Return the newest record whose top-level field equals ``value``, else ``None``."""
        raise NotImplementedError


def storage_backend_name(explicit: str | None = None) -> str:
    """Resolve the storage backend from ``explicit`` or ``FORM_STORAGE`` (default ``jsonl``)."""
    return (explicit or os.getenv("FORM_STORAGE", "jsonl")).lower()


def create_store(
    data_dir: Path,
    kind: StoreKind,
    *,
    backend: str | None = None,
) -> JsonlStore | SqliteStore:
    """Build a record store for ``kind`` under ``data_dir``.

    Backend selection (first match wins):

    1. ``backend`` argument
    2. ``FORM_STORAGE`` env (``jsonl`` default, or ``sqlite``)
    """
    name = storage_backend_name(backend)
    if name == "sqlite":
        return SqliteStore(data_dir / "form.db", _SQLITE_TABLES[kind])
    if name != "jsonl":
        msg = f"unknown FORM_STORAGE backend {name!r} (want jsonl or sqlite)"
        raise ValueError(msg)
    return JsonlStore(data_dir / _JSONL_FILES[kind])


__all__ = [
    "JsonlStore",
    "RecordStore",
    "SqliteStore",
    "StoreKind",
    "create_store",
    "migrate_jsonl_to_sqlite",
    "storage_backend_name",
]
