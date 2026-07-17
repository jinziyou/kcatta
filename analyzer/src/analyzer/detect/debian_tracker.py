"""Bounded-memory Debian Security Tracker index and exact-origin lookups."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import threading
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
INDEX_FILENAME = "index.sqlite3"
INDEX_SCHEMA_VERSION = "2"
DEFAULT_MAX_AGE_SECONDS = 48 * 60 * 60


@dataclass(frozen=True)
class DebianTrackerAdvisory:
    advisory_id: str
    release: str
    status: str
    fixed_version: str | None
    urgency: str | None
    scope: str | None


class DebianTrackerStore:
    """Read-only advisory index keyed by exact Debian source package/version."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        record_count: int = 0,
        source_package_count: int = 0,
        synced_at: datetime | None = None,
        max_age_seconds: float | None = None,
    ) -> None:
        self.path = path
        self.record_count = record_count
        self.source_package_count = source_package_count
        self.synced_at = synced_at
        self.max_age_seconds = max_age_seconds
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.RLock()

    @property
    def available(self) -> bool:
        return self.path is not None and self.record_count > 0

    def age_seconds(self, now: datetime | None = None) -> float | None:
        if self.synced_at is None:
            return None
        current = now or datetime.now(UTC)
        return max(0.0, (current - self.synced_at).total_seconds())

    @property
    def stale(self) -> bool:
        age = self.age_seconds()
        return bool(
            self.available
            and self.max_age_seconds is not None
            and (age is None or age > self.max_age_seconds)
        )

    def lookup(self, source_package: str, source_version: str) -> list[DebianTrackerAdvisory]:
        if self.path is None:
            return []
        with self._lock:
            if self._connection is None:
                quoted = urllib.parse.quote(str(self.path.resolve()), safe="/")
                self._connection = sqlite3.connect(
                    f"file:{quoted}?mode=ro&immutable=1",
                    uri=True,
                    check_same_thread=False,
                )
                self._connection.execute("PRAGMA query_only=ON")
            rows = self._connection.execute(
                """
                SELECT advisory_id, release, status, fixed_version, urgency, scope
                FROM advisories
                WHERE source_package = ? AND source_version = ?
                ORDER BY advisory_id, release
                """,
                (source_package, source_version),
            ).fetchall()
        return [DebianTrackerAdvisory(*row) for row in rows]

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    @classmethod
    def load(
        cls,
        directory: str | Path,
        *,
        max_age_seconds: float | None = None,
    ) -> DebianTrackerStore:
        path = Path(directory) / INDEX_FILENAME
        if not path.is_file():
            return cls(max_age_seconds=max_age_seconds)
        quoted = urllib.parse.quote(str(path.resolve()), safe="/")
        try:
            with sqlite3.connect(f"file:{quoted}?mode=ro&immutable=1", uri=True) as connection:
                metadata = dict(connection.execute("SELECT key, value FROM metadata"))
                if metadata.get("schema_version") != INDEX_SCHEMA_VERSION:
                    return cls(max_age_seconds=max_age_seconds)
                record_count = int(metadata.get("record_count", "-1"))
                source_count = int(metadata.get("source_package_count", "-1"))
                synced_at = datetime.fromisoformat(metadata["synced_at"])
                if synced_at.tzinfo is None:
                    raise ValueError("synced_at must include a timezone")
                synced_at = synced_at.astimezone(UTC)
                if record_count <= 0 or source_count <= 0:
                    return cls(max_age_seconds=max_age_seconds)
                if connection.execute("SELECT 1 FROM advisories LIMIT 1").fetchone() is None:
                    return cls(max_age_seconds=max_age_seconds)
        except (KeyError, OSError, sqlite3.DatabaseError, TypeError, ValueError):
            return cls(max_age_seconds=max_age_seconds)
        return cls(
            path,
            record_count=record_count,
            source_package_count=source_count,
            synced_at=synced_at,
            max_age_seconds=max_age_seconds,
        )


def _decode_at(
    decoder: json.JSONDecoder,
    stream: IO[str],
    buffer: str,
    position: int,
) -> tuple[object, int, str]:
    while True:
        try:
            value, end = decoder.raw_decode(buffer, position)
            return value, end, buffer
        except json.JSONDecodeError:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                raise
            buffer += chunk


def iter_tracker_packages(stream: IO[str]) -> Iterator[tuple[str, dict]]:
    """Yield top-level package objects without loading the ~80 MiB feed at once."""
    decoder = json.JSONDecoder()
    buffer = stream.read(1024 * 1024)
    position = 0

    def skip_space() -> None:
        nonlocal buffer, position
        while True:
            while position < len(buffer) and buffer[position].isspace():
                position += 1
            if position < len(buffer):
                return
            chunk = stream.read(1024 * 1024)
            if not chunk:
                return
            buffer = buffer[position:] + chunk
            position = 0

    skip_space()
    if position >= len(buffer) or buffer[position] != "{":
        raise ValueError("Debian tracker feed must be a top-level JSON object")
    position += 1
    while True:
        skip_space()
        if position < len(buffer) and buffer[position] == "}":
            return
        key, position, buffer = _decode_at(decoder, stream, buffer, position)
        if not isinstance(key, str):
            raise ValueError("Debian tracker package key must be a string")
        skip_space()
        if position >= len(buffer) or buffer[position] != ":":
            raise ValueError("Debian tracker package key is missing ':'")
        position += 1
        skip_space()
        value, position, buffer = _decode_at(decoder, stream, buffer, position)
        if not isinstance(value, dict):
            raise ValueError(f"Debian tracker package {key!r} must contain an object")
        yield key, value
        skip_space()
        if position < len(buffer) and buffer[position] == "}":
            return
        if position >= len(buffer) or buffer[position] != ",":
            raise ValueError("Debian tracker package entries must be comma-separated")
        position += 1
        if position > 4 * 1024 * 1024:
            buffer = buffer[position:]
            position = 0


class _IndexWriter:
    def __init__(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{INDEX_FILENAME}.", suffix=".tmp", dir=directory
        )
        os.close(descriptor)
        self.directory = directory
        self.temporary = Path(temporary)
        self.target = directory / INDEX_FILENAME
        self.connection = sqlite3.connect(self.temporary)
        self.connection.execute("PRAGMA journal_mode=OFF")
        self.connection.execute("PRAGMA synchronous=OFF")
        self.connection.executescript(
            """
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE advisories (
                source_package TEXT NOT NULL,
                source_version TEXT NOT NULL,
                advisory_id TEXT NOT NULL,
                release TEXT NOT NULL,
                status TEXT NOT NULL,
                fixed_version TEXT,
                urgency TEXT,
                scope TEXT,
                PRIMARY KEY (source_package, source_version, advisory_id, release)
            ) WITHOUT ROWID;
            """
        )
        self.closed = False

    def add_package(self, source_package: str, issues: dict) -> None:
        for advisory_id, issue in issues.items():
            if not isinstance(advisory_id, str) or not isinstance(issue, dict):
                continue
            scope = issue.get("scope")
            scope = scope if isinstance(scope, str) else None
            releases = issue.get("releases")
            if not isinstance(releases, dict):
                continue
            for release, release_data in releases.items():
                if not isinstance(release, str) or not isinstance(release_data, dict):
                    continue
                status = release_data.get("status")
                repositories = release_data.get("repositories")
                if not isinstance(status, str) or not isinstance(repositories, dict):
                    continue
                fixed_version = release_data.get("fixed_version")
                fixed_version = fixed_version if isinstance(fixed_version, str) else None
                urgency = release_data.get("urgency")
                urgency = urgency if isinstance(urgency, str) else None
                versions = {
                    version
                    for version in repositories.values()
                    if isinstance(version, str) and version.strip()
                }
                self.connection.executemany(
                    """
                    INSERT OR REPLACE INTO advisories(
                        source_package, source_version, advisory_id, release,
                        status, fixed_version, urgency, scope
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            source_package,
                            version,
                            advisory_id,
                            release,
                            status,
                            fixed_version,
                            urgency,
                            scope,
                        )
                        for version in versions
                    ),
                )

    def finish(self) -> tuple[int, int]:
        record_count = int(self.connection.execute("SELECT COUNT(*) FROM advisories").fetchone()[0])
        source_count = int(
            self.connection.execute(
                "SELECT COUNT(DISTINCT source_package) FROM advisories"
            ).fetchone()[0]
        )
        if record_count <= 0 or source_count <= 0:
            raise OSError("Debian tracker feed contained no usable repository-version records")
        self.connection.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            (
                ("schema_version", INDEX_SCHEMA_VERSION),
                ("record_count", str(record_count)),
                ("source_package_count", str(source_count)),
                ("synced_at", datetime.now(UTC).isoformat()),
                ("source", TRACKER_URL),
            ),
        )
        self.connection.commit()
        self.connection.close()
        self.closed = True
        descriptor = os.open(self.temporary, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(self.temporary, self.target)
        directory_descriptor = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return record_count, source_count

    def abort(self) -> None:
        if not self.closed:
            self.connection.close()
            self.closed = True
        self.temporary.unlink(missing_ok=True)


def _build_index(stream: IO[str], directory: Path) -> tuple[int, int]:
    writer = _IndexWriter(directory)
    try:
        for source_package, issues in iter_tracker_packages(stream):
            writer.add_package(source_package, issues)
        return writer.finish()
    except Exception:
        writer.abort()
        raise


def sync_debian_tracker(
    directory: str | Path,
    *,
    json_file: str | Path | None = None,
    timeout: float = 120.0,
) -> tuple[int, int]:
    """Build an atomic local index from an official feed or downloaded JSON file."""
    target = Path(directory)
    if json_file is not None:
        with Path(json_file).open(encoding="utf-8") as stream:
            return _build_index(stream, target)

    with (
        urllib.request.urlopen(TRACKER_URL, timeout=timeout) as response,  # noqa: S310
        tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as downloaded,
    ):
        shutil.copyfileobj(response, downloaded, length=1024 * 1024)
        downloaded.seek(0)
        with open(downloaded.fileno(), encoding="utf-8", closefd=False) as stream:
            return _build_index(stream, target)
