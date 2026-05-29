"""Local OSV advisory store.

Loads OSV JSON records from a directory tree (one record per file, as
produced by the OSV exports) and indexes them by ``(ecosystem, package
name)`` for fast lookup during detection. Kept deliberately simple: the
whole index lives in memory, which is fine for per-ecosystem deb data and
mirrors the JSONL store's "swap it out when it outgrows memory" stance.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .osv import OsvRecord


class OsvStore:
    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], list[OsvRecord]] = defaultdict(list)
        self._ids: set[str] = set()

    @property
    def record_count(self) -> int:
        return len(self._ids)

    def add(self, raw: dict) -> None:
        if "id" not in raw or raw["id"] in self._ids:
            return
        record = OsvRecord.from_dict(raw)
        self._ids.add(record.id)
        for entry in record.affected:
            pkg = entry.get("package", {})
            ecosystem, name = pkg.get("ecosystem"), pkg.get("name")
            if ecosystem and name:
                self._by_key[(ecosystem, name)].append(record)

    def lookup(self, ecosystem: str, name: str) -> list[OsvRecord]:
        return self._by_key.get((ecosystem, name), [])

    @classmethod
    def load_dir(cls, directory: str | Path) -> OsvStore:
        store = cls()
        root = Path(directory)
        if not root.exists():
            return store
        for path in sorted(root.rglob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            records = data if isinstance(data, list) else [data]
            for raw in records:
                if isinstance(raw, dict):
                    store.add(raw)
        return store
