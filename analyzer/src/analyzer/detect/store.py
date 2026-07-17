"""Bounded-memory local OSV advisory store.

Each top-level ecosystem directory carries a compact SQLite package index.
Startup reads only index metadata; a lookup fetches and decodes just the
advisories for one exact ``(ecosystem, package name)`` key.  Legacy JSON-only
ecosystem directories are indexed once, with an atomic file replacement, so a
large corpus never has to become a graph of resident Python objects.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import tempfile
import threading
import urllib.parse
import zlib
from collections import defaultdict
from pathlib import Path

from .osv import OsvRecord

logger = logging.getLogger(__name__)

INDEX_FILENAME = ".index.sqlite3"
INDEX_SCHEMA_VERSION = "1"


def _ecosystem_family(ecosystem: str) -> str:
    return ecosystem.split(":", 1)[0].strip()


def _record_payload(record: OsvRecord) -> bytes:
    """Encode only fields used by detection, compressed for a compact index."""
    raw = {
        "id": record.id,
        "aliases": record.aliases,
        "affected": record.affected,
        "references": record.references,
        "severity_word": record.severity_word,
        "cvss_vector": record.cvss_vector,
        "cvss_v4_vector": record.cvss_v4_vector,
        "withdrawn": record.withdrawn,
    }
    encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return zlib.compress(encoded, level=1)


def _decode_record(payload: bytes) -> OsvRecord:
    raw = json.loads(zlib.decompress(payload).decode("utf-8"))
    return OsvRecord(**raw)


def _read_json(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    values = data if isinstance(data, list) else [data]
    return [value for value in values if isinstance(value, dict)]


class OsvIndexWriter:
    """Atomically build one immutable, top-level ecosystem package index."""

    def __init__(self, directory: str | Path, ecosystem: str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ecosystem = ecosystem
        self.record_count = 0
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{INDEX_FILENAME}.", suffix=".tmp", dir=self.directory
        )
        os.close(descriptor)
        self._temporary = Path(temporary)
        self._target = self.directory / INDEX_FILENAME
        self._conn = sqlite3.connect(self._temporary)
        # The database itself is staged and fsynced before an atomic rename, so
        # a rollback journal and per-statement sync add cost without safety.
        self._conn.execute("PRAGMA journal_mode=OFF")
        self._conn.execute("PRAGMA synchronous=OFF")
        self._conn.executescript(
            """
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE records (
                record_id TEXT PRIMARY KEY,
                payload BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE packages (
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                record_id TEXT NOT NULL,
                PRIMARY KEY (ecosystem, package_name, record_id)
            ) WITHOUT ROWID;
            """
        )
        self._closed = False

    def __enter__(self) -> OsvIndexWriter:
        return self

    def add(self, raw: dict) -> bool:
        """Add a valid record and its matchable keys for this index family."""
        try:
            record = OsvRecord.from_dict(raw)
        except (KeyError, TypeError, ValueError):
            return False
        if record.withdrawn:
            return False

        keys: set[tuple[str, str]] = set()
        for entry in record.affected:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package")
            if not isinstance(package, dict):
                continue
            ecosystem = package.get("ecosystem")
            package_name = package.get("name")
            ranges = entry.get("ranges")
            versions = entry.get("versions")
            matchable = (isinstance(ranges, list) and bool(ranges)) or (
                isinstance(versions, list) and bool(versions)
            )
            if (
                isinstance(ecosystem, str)
                and _ecosystem_family(ecosystem) == self.ecosystem
                and isinstance(package_name, str)
                and package_name.strip()
                and matchable
            ):
                keys.add((ecosystem, package_name))
        if not keys:
            return False

        # A duplicate record id in an export is resolved deterministically by
        # the last archive member. Avoid a resident id set for normal unique
        # exports; the slower key cleanup runs only on an actual duplicate.
        payload = sqlite3.Binary(_record_payload(record))
        inserted = self._conn.execute(
            "INSERT OR IGNORE INTO records(record_id, payload) VALUES (?, ?)",
            (record.id, payload),
        ).rowcount
        if not inserted:
            self._conn.execute(
                "UPDATE records SET payload = ? WHERE record_id = ?",
                (payload, record.id),
            )
            self._conn.execute("DELETE FROM packages WHERE record_id = ?", (record.id,))
        self._conn.executemany(
            "INSERT INTO packages(ecosystem, package_name, record_id) VALUES (?, ?, ?)",
            ((ecosystem, name, record.id) for ecosystem, name in sorted(keys)),
        )
        return True

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # type: ignore[no-untyped-def]
        if exc_type is not None:
            self._abort()
            return
        try:
            self.record_count = int(
                self._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            )
            self._conn.executemany(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                (
                    ("schema_version", INDEX_SCHEMA_VERSION),
                    ("ecosystem", self.ecosystem),
                    ("record_count", str(self.record_count)),
                ),
            )
            self._conn.commit()
            self._conn.close()
            self._closed = True
            descriptor = os.open(self._temporary, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(self._temporary, self._target)
            try:
                directory_descriptor = os.open(
                    self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                )
            except OSError:
                directory_descriptor = None
            if directory_descriptor is not None:
                try:
                    os.fsync(directory_descriptor)
                except OSError:
                    pass
                finally:
                    os.close(directory_descriptor)
        except Exception:
            self._abort()
            raise

    def _abort(self) -> None:
        if not self._closed:
            self._conn.close()
            self._closed = True
        self._temporary.unlink(missing_ok=True)


def build_ecosystem_index(directory: str | Path, ecosystem: str) -> int:
    """Build an index from a legacy JSON-only ecosystem directory."""
    root = Path(directory)
    with OsvIndexWriter(root, ecosystem) as writer:
        for path in sorted(root.rglob("*.json")):
            for raw in _read_json(path):
                writer.add(raw)
    return writer.record_count


def _read_index_count(path: Path, ecosystem: str) -> int | None:
    """Validate immutable index metadata without scanning the advisory table.

    The count and all index rows are committed in the same SQLite transaction,
    then the database is fsynced and atomically renamed. Re-counting a cold
    multi-gigabyte B-tree at every API start defeats bounded startup, so only
    metadata/schema consistency and a one-row readability probe happen here.
    """
    quoted = urllib.parse.quote(str(path.resolve()), safe="/")
    try:
        with sqlite3.connect(f"file:{quoted}?mode=ro&immutable=1", uri=True) as conn:
            metadata = dict(conn.execute("SELECT key, value FROM metadata"))
            if (
                metadata.get("schema_version") != INDEX_SCHEMA_VERSION
                or metadata.get("ecosystem") != ecosystem
            ):
                return None
            declared = int(metadata.get("record_count", "-1"))
            if declared < 0:
                return None
            has_record = conn.execute("SELECT 1 FROM records LIMIT 1").fetchone() is not None
            if has_record != (declared > 0):
                return None
            # Confirm the lookup table exists and is readable without walking it.
            conn.execute("SELECT 1 FROM packages LIMIT 1").fetchone()
            return declared
    except (OSError, sqlite3.DatabaseError, TypeError, ValueError):
        return None


class OsvStore:
    """Disk-backed OSV index with a small compatibility in-memory overlay."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], list[OsvRecord]] = defaultdict(list)
        self._ids: set[str] = set()
        self._indexed_keys: set[tuple[str, str, str]] = set()
        self._ecosystem_ids: dict[str, set[str]] = defaultdict(set)
        self._index_paths: dict[str, Path] = {}
        self._index_counts: dict[str, int] = {}
        self._connections: dict[str, sqlite3.Connection] = {}
        self._connection_lock = threading.RLock()

    @property
    def record_count(self) -> int:
        """Number of usable advisory records available across index snapshots."""
        return sum(self._index_counts.values()) + len(self._ids)

    @property
    def ecosystem_record_counts(self) -> dict[str, int]:
        """Usable advisory counts for each top-level ecosystem."""
        counts = dict(self._index_counts)
        for ecosystem, ids in self._ecosystem_ids.items():
            counts[ecosystem] = counts.get(ecosystem, 0) + len(ids)
        return counts

    @property
    def disk_backed_ecosystems(self) -> frozenset[str]:
        """Top-level ecosystems served without resident advisory objects."""
        return frozenset(self._index_paths)

    def add(self, raw: dict) -> None:
        """Add one record to the small in-memory compatibility overlay."""
        record_id = raw.get("id")
        if not isinstance(record_id, str) or not record_id.strip():
            return
        record = OsvRecord.from_dict(raw)
        if record.withdrawn:
            return
        indexed = False
        for entry in record.affected:
            pkg = entry.get("package", {})
            ecosystem, name = pkg.get("ecosystem"), pkg.get("name")
            ranges = entry.get("ranges")
            versions = entry.get("versions")
            matchable = (isinstance(ranges, list) and bool(ranges)) or (
                isinstance(versions, list) and bool(versions)
            )
            if ecosystem and name and matchable:
                index_key = (record.id, ecosystem, name)
                if index_key not in self._indexed_keys:
                    self._indexed_keys.add(index_key)
                    self._by_key[(ecosystem, name)].append(record)
                self._ecosystem_ids[_ecosystem_family(ecosystem)].add(record.id)
                indexed = True
        if indexed:
            self._ids.add(record.id)

    def lookup(self, ecosystem: str, name: str) -> list[OsvRecord]:
        """Return records for one exact ecosystem/package key."""
        records = list(self._by_key.get((ecosystem, name), ()))
        family = _ecosystem_family(ecosystem)
        path = self._index_paths.get(family)
        if path is None:
            return records

        with self._connection_lock:
            conn = self._connections.get(family)
            if conn is None:
                quoted = urllib.parse.quote(str(path.resolve()), safe="/")
                conn = sqlite3.connect(
                    f"file:{quoted}?mode=ro&immutable=1",
                    uri=True,
                    check_same_thread=False,
                )
                conn.execute("PRAGMA query_only=ON")
                self._connections[family] = conn
            payloads = [
                row[0]
                for row in conn.execute(
                    """
                    SELECT records.payload
                    FROM packages
                    JOIN records USING (record_id)
                    WHERE packages.ecosystem = ? AND packages.package_name = ?
                    ORDER BY packages.record_id
                    """,
                    (ecosystem, name),
                )
            ]
        records.extend(_decode_record(payload) for payload in payloads)
        return records

    def close(self) -> None:
        """Close lazily opened read-only index connections."""
        with self._connection_lock:
            for connection in self._connections.values():
                connection.close()
            self._connections.clear()

    @classmethod
    def load_dir(cls, directory: str | Path) -> OsvStore:
        """Open or build per-ecosystem indexes without loading their records."""
        store = cls()
        root = Path(directory)
        if not root.exists():
            return store

        # Direct root JSON is a legacy/test layout. Keep its small compatibility
        # overlay, while normal top-level ecosystem directories remain disk-backed.
        for path in sorted(root.glob("*.json")):
            for raw in _read_json(path):
                try:
                    store.add(raw)
                except (KeyError, TypeError, ValueError):
                    continue

        for ecosystem_dir in sorted(path for path in root.iterdir() if path.is_dir()):
            ecosystem = ecosystem_dir.name
            if ecosystem.startswith("."):
                continue
            index_path = ecosystem_dir / INDEX_FILENAME
            count = _read_index_count(index_path, ecosystem) if index_path.exists() else None
            if count is None:
                try:
                    has_json = next(ecosystem_dir.rglob("*.json"), None) is not None
                    if not has_json:
                        continue
                    count = build_ecosystem_index(ecosystem_dir, ecosystem)
                except OSError as exc:
                    logger.warning(
                        "cannot build disk-backed OSV index for %s at %s: %s",
                        ecosystem,
                        ecosystem_dir,
                        exc,
                    )
                    continue
            if count == 0:
                # Compatibility for old hand-built layouts whose folder name is
                # not the OSV family (for example ``Rocky/`` containing
                # ``Rocky Linux:9``). Official sync snapshots always use the
                # exact family and therefore stay fully disk-backed.
                for path in sorted(ecosystem_dir.rglob("*.json")):
                    for raw in _read_json(path):
                        try:
                            store.add(raw)
                        except (KeyError, TypeError, ValueError):
                            continue
                continue
            store._index_paths[ecosystem] = index_path
            store._index_counts[ecosystem] = count
        return store
