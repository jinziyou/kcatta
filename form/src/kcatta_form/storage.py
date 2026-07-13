"""Form-owned persistence factory built on the shared store primitives."""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from pathlib import Path

from analyzer.storage import JsonlStore, SqliteStore, StoreKind, create_store

FORM_SQLITE_FILENAME = "form.db"
logger = logging.getLogger(__name__)


def create_form_store(
    data_dir: Path,
    kind: StoreKind,
    *,
    backend: str,
) -> JsonlStore | SqliteStore:
    """Create a Form control store without reusing Analyzer's DB filename."""
    return create_store(
        data_dir,
        kind,
        backend=backend,
        sqlite_filename=FORM_SQLITE_FILENAME,
    )


def latest_legacy_scan_jobs(store: JsonlStore | SqliteStore) -> list[dict]:
    """Read every legacy job's newest append-only row for one-time queue import.

    This intentionally does not use ``tail(1000)``: an old pending job must not
    disappear merely because newer jobs accumulated many state transitions.
    """
    if isinstance(store, SqliteStore):
        with closing(sqlite3.connect(store.db_path)) as connection:
            rows = connection.execute(
                f"""
                SELECT source.payload
                FROM {store.table} AS source
                JOIN (
                    SELECT json_extract(payload, '$.job_id') AS job_id, MAX(id) AS latest_id
                    FROM {store.table}
                    WHERE json_extract(payload, '$.job_id') IS NOT NULL
                    GROUP BY json_extract(payload, '$.job_id')
                ) AS latest ON source.id = latest.latest_id
                ORDER BY source.id ASC
                """
            )
            return [json.loads(str(row[0])) for row in rows]

    if not store.path.exists():
        return []
    newest: dict[str, dict] = {}
    with store.path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError:
                logger.warning(
                    "skipping malformed legacy scan-job row %s:%d",
                    store.path,
                    line_number,
                )
                continue
            job_id = record.get("job_id") if isinstance(record, dict) else None
            if isinstance(job_id, str):
                newest[job_id] = record
    return list(newest.values())


__all__ = ["FORM_SQLITE_FILENAME", "create_form_store", "latest_legacy_scan_jobs"]
