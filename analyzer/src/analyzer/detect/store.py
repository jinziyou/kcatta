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
    """In-memory index of OSV records keyed by ``(ecosystem, package name)``."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], list[OsvRecord]] = defaultdict(list)
        self._ids: set[str] = set()

    @property
    def record_count(self) -> int:
        """Number of distinct OSV records held in the store."""
        return len(self._ids)

    def add(self, raw: dict) -> None:
        """Index one raw OSV record.

        Skips entries with no id, a duplicate id, or a ``withdrawn`` marker. A
        withdrawn advisory has been rescinded by its source — indexing it would
        produce a finding that is a false positive forever (it never ages out),
        so it is dropped here and not counted in ``record_count``.
        """
        if "id" not in raw or raw["id"] in self._ids:
            return
        record = OsvRecord.from_dict(raw)
        if record.withdrawn:
            return
        self._ids.add(record.id)
        for entry in record.affected:
            pkg = entry.get("package", {})
            ecosystem, name = pkg.get("ecosystem"), pkg.get("name")
            if ecosystem and name:
                self._by_key[(ecosystem, name)].append(record)

    def lookup(self, ecosystem: str, name: str) -> list[OsvRecord]:
        """Return all records affecting the given ecosystem/package, or an empty list."""
        return self._by_key.get((ecosystem, name), [])

    @classmethod
    def load_dir(cls, directory: str | Path) -> OsvStore:
        """Build a store by loading every ``*.json`` OSV record under ``directory``.

        A missing directory yields an empty store; unreadable or malformed
        files are skipped silently.
        """
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
