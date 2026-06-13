"""Migrate legacy JSONL persistence into SQLite."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from ..schemas import (
    Alert,
    AssetReport,
    CapabilityGraph,
    DetectionResult,
    FlowBatch,
    GuardEventBatch,
    ScanJob,
    ScanTarget,
)
from .sqlite import (
    TABLE_ALERTS,
    TABLE_ASSET_REPORTS,
    TABLE_CAPABILITY_GRAPHS,
    TABLE_FLOW_BATCHES,
    TABLE_GUARD_EVENTS,
    TABLE_SCAN_JOBS,
    TABLE_SCAN_TARGETS,
    TABLE_VULNERABILITIES,
    SqliteStore,
)

_MIGRATIONS: tuple[tuple[str, str, type[BaseModel]], ...] = (
    ("asset-reports.jsonl", TABLE_ASSET_REPORTS, AssetReport),
    ("flow-batches.jsonl", TABLE_FLOW_BATCHES, FlowBatch),
    ("guard-events.jsonl", TABLE_GUARD_EVENTS, GuardEventBatch),
    ("vulnerabilities.jsonl", TABLE_VULNERABILITIES, DetectionResult),
    ("alerts.jsonl", TABLE_ALERTS, Alert),
    ("capability-graphs.jsonl", TABLE_CAPABILITY_GRAPHS, CapabilityGraph),
    ("scan-targets.jsonl", TABLE_SCAN_TARGETS, ScanTarget),
    ("scan-jobs.jsonl", TABLE_SCAN_JOBS, ScanJob),
)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records: list[dict] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        try:
            records.append(json.loads(text))
        except json.JSONDecodeError as exc:
            msg = f"{path}:{line_no}: invalid JSON: {exc}"
            raise ValueError(msg) from exc
    return records


def _sqlite_row_count(store: SqliteStore) -> int:
    import sqlite3

    with sqlite3.connect(store.db_path) as conn:
        row = conn.execute(f"SELECT COUNT(*) FROM {store.table}").fetchone()
    return int(row[0]) if row else 0


def migrate_jsonl_to_sqlite(data_dir: Path, *, force: bool = False) -> dict[str, int]:
    """Copy all JSONL records under ``data_dir`` into ``analyzer.db``.

    Returns per-table import counts. Skips tables that already contain rows
    unless ``force`` is set (append either way when forced).
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "analyzer.db"
    counts: dict[str, int] = {}

    for jsonl_name, table, model in _MIGRATIONS:
        sqlite = SqliteStore(db_path, table)
        existing = _sqlite_row_count(sqlite)
        if existing and not force:
            counts[table] = 0
            continue

        jsonl_path = data_dir / jsonl_name
        imported = 0
        for raw in _read_jsonl(jsonl_path):
            try:
                record = model.model_validate(raw)
            except ValidationError as exc:
                msg = f"{jsonl_path}: record failed validation: {exc}"
                raise ValueError(msg) from exc
            sqlite.append(record)
            imported += 1
        counts[table] = imported

    return counts
