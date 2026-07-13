"""Shared JSONL/SQLite record persistence for Analyzer and Form."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from .errors import StorageCapacityError
from .jsonl import JsonlStore
from .migrate import migrate_jsonl_to_sqlite
from .sqlite import (
    TABLE_ALERT_STATES,
    TABLE_ALERTS,
    TABLE_ASSET_REPORTS,
    TABLE_CAPABILITY_GRAPHS,
    TABLE_GUARD_EVENTS,
    TABLE_SCAN_JOBS,
    TABLE_SCAN_TARGETS,
    TABLE_TRACE_BATCHES,
    TABLE_VULNERABILITIES,
    SqliteStore,
)

StoreKind = Literal[
    "asset_reports",
    "trace_batches",
    "guard_events",
    "vulnerabilities",
    "alerts",
    "alert_states",
    "capability_graphs",
    # Shared generic stores used by Form's control plane. Analyzer's app does
    # not initialize or own these states.
    "scan_targets",
    "scan_jobs",
]

_JSONL_FILES: dict[StoreKind, str] = {
    "asset_reports": "asset-reports.jsonl",
    "trace_batches": "trace-batches.jsonl",
    "guard_events": "guard-events.jsonl",
    "vulnerabilities": "vulnerabilities.jsonl",
    "alerts": "alerts.jsonl",
    "alert_states": "alert-states.jsonl",
    "capability_graphs": "capability-graphs.jsonl",
    "scan_targets": "scan-targets.jsonl",
    "scan_jobs": "scan-jobs.jsonl",
}

_SQLITE_TABLES: dict[StoreKind, str] = {
    "asset_reports": TABLE_ASSET_REPORTS,
    "trace_batches": TABLE_TRACE_BATCHES,
    "guard_events": TABLE_GUARD_EVENTS,
    "vulnerabilities": TABLE_VULNERABILITIES,
    "alerts": TABLE_ALERTS,
    "alert_states": TABLE_ALERT_STATES,
    "capability_graphs": TABLE_CAPABILITY_GRAPHS,
    "scan_targets": TABLE_SCAN_TARGETS,
    "scan_jobs": TABLE_SCAN_JOBS,
}


def storage_backend_name(explicit: str | None = None) -> str:
    """Resolve the storage backend from ``explicit`` or ``ANALYZER_STORAGE`` (default ``jsonl``)."""
    return (explicit or os.getenv("ANALYZER_STORAGE", "jsonl")).lower()


def create_store(
    data_dir: Path,
    kind: StoreKind,
    *,
    backend: str | None = None,
    sqlite_filename: str = "analyzer.db",
) -> JsonlStore | SqliteStore:
    """Build a record store for ``kind`` under ``data_dir``.

    Backend selection (first match wins):

    1. ``backend`` argument
    2. ``ANALYZER_STORAGE`` env (``jsonl`` default, or ``sqlite``)
    """
    name = storage_backend_name(backend)
    if name == "sqlite":
        if Path(sqlite_filename).name != sqlite_filename:
            raise ValueError("sqlite_filename must be a plain filename")
        return SqliteStore(data_dir / sqlite_filename, _SQLITE_TABLES[kind])
    if name != "jsonl":
        msg = f"unknown ANALYZER_STORAGE backend {name!r} (want jsonl or sqlite)"
        raise ValueError(msg)
    return JsonlStore(data_dir / _JSONL_FILES[kind])


__all__ = [
    "JsonlStore",
    "SqliteStore",
    "StorageCapacityError",
    "StoreKind",
    "create_store",
    "migrate_jsonl_to_sqlite",
    "storage_backend_name",
]
