"""Append-only JSONL store.

The store is intentionally small: one Pydantic model per line, flushed
immediately so a crash never loses an acknowledged record. This is the
right primitive for v0 ingest -- a real deployment will swap it for a
proper datastore once query / retention / dedup requirements arrive.

Single-writer only: concurrent appenders (e.g. multiple worker processes)
can interleave writes. For multi-worker deployments use ``SqliteStore``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)


def _parse_lines(lines: Iterable[str]) -> Iterator[dict]:
    """Parse JSONL lines, skipping blank lines and tolerating a corrupt or
    truncated line (e.g. a half-written record left by a crash) rather than
    failing the whole read. Shared by ``tail`` and ``find_one`` so both apply
    the same resilience."""
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            yield json.loads(text)
        except json.JSONDecodeError:
            logger.warning("skipping malformed JSONL line in store")
            continue


class JsonlStore:
    """Append Pydantic models to a JSONL file, one per line.

    The store opens the file lazily on first write, so creating an
    instance pointed at a not-yet-existing path is cheap and safe.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        """Filesystem path of the backing JSONL file."""
        return self._path

    def append(self, record: BaseModel) -> None:
        """Append a model as one JSON line, flushed immediately so it survives a crash."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = record.model_dump_json()
        with self._path.open("a", encoding="utf-8") as fh:
            # Single write (line + newline) under O_APPEND to minimize the chance
            # of interleaving with a concurrent writer.
            fh.write(line + "\n")
            fh.flush()

    def tail(self, limit: int) -> list[dict]:
        """Return up to ``limit`` most recent records, newest first.

        Reads the whole file -- adequate for v0 sizes. When JSONL
        outgrows memory the right move is to replace ``JsonlStore``
        entirely rather than to optimize ``tail``. Blank/corrupt lines
        (e.g. a crash-truncated final record) are skipped, not fatal.
        """
        if limit <= 0 or not self._path.exists():
            return []
        with self._path.open(encoding="utf-8") as fh:
            lines = fh.readlines()
        recent = lines[-limit:]
        return list(_parse_lines(reversed(recent)))

    def find_one(self, field: str, value: str) -> dict | None:
        """Return the newest record whose top-level JSON field equals ``value``.

        Scans the WHOLE file (newest first) for parity with ``SqliteStore.find_one``,
        which queries the entire table — both backends must resolve the same id to the
        same record regardless of how many newer records exist.
        """
        if not self._path.exists():
            return None
        with self._path.open(encoding="utf-8") as fh:
            lines = fh.readlines()
        for record in _parse_lines(reversed(lines)):
            if record.get(field) == value:
                return record
        return None
