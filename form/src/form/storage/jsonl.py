"""Append-only JSONL store.

The store is intentionally small: one Pydantic model per line, flushed
immediately so a crash never loses an acknowledged record. This is the
right primitive for v0 ingest -- a real deployment will swap it for a
proper datastore once query / retention / dedup requirements arrive.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel


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
            fh.write(line)
            fh.write("\n")
            fh.flush()

    def tail(self, limit: int) -> list[dict]:
        """Return up to ``limit`` most recent records, newest first.

        Reads the whole file -- adequate for v0 sizes. When JSONL
        outgrows memory the right move is to replace ``JsonlStore``
        entirely rather than to optimize ``tail``.
        """
        if limit <= 0 or not self._path.exists():
            return []
        with self._path.open(encoding="utf-8") as fh:
            lines = fh.readlines()
        recent = lines[-limit:]
        return [json.loads(line) for line in reversed(recent)]

    def find_one(self, field: str, value: str, *, scan_limit: int = 500) -> dict | None:
        """Return the newest record whose top-level JSON field equals ``value``."""
        for record in self.tail(scan_limit):
            if record.get(field) == value:
                return record
        return None
