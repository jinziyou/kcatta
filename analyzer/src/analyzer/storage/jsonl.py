"""Append-only JSONL store.

The store is intentionally small: one Pydantic model per line, flushed
immediately so a crash never loses an acknowledged record. This is the
right primitive for v0 ingest -- a real deployment will swap it for a
proper datastore once query / retention / dedup requirements arrive.

F1 scalability: ``tail`` reads from the *end* of the file in bounded chunks
rather than loading the whole file into memory, and ``append`` enforces an
optional size/line retention cap (rolling the file over) so an unbounded ingest
stream cannot grow a single JSONL file without limit.

Single-writer only: concurrent appenders (e.g. multiple worker processes)
can interleave writes. For multi-worker deployments use ``SqliteStore``.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import shutil
import tempfile
import threading
from collections.abc import Iterable, Iterator
from contextlib import suppress
from pathlib import Path

from pydantic import BaseModel

from .errors import StorageCapacityError

logger = logging.getLogger(__name__)

# Production-safe retention defaults (overridable via env). Explicit 0 disables
# a cap for deployments whose filesystem already enforces a stricter quota.
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_LINES = 0
DEFAULT_MAX_RECORD_BYTES = 12 * 1024 * 1024
DEFAULT_READ_MAX_BYTES = 32 * 1024 * 1024

# Block size used when reading the file tail backwards.
_TAIL_CHUNK = 64 * 1024


def _nonnegative_limit(explicit: int | None, env_name: str, default: int) -> int:
    raw: int | str = explicit if explicit is not None else os.getenv(env_name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{env_name} must be a non-negative integer") from exc
    if value < 0:
        raise ValueError(f"{env_name} must be a non-negative integer")
    return value


def _bool_setting(explicit: bool | None, env_name: str, default: bool) -> bool:
    if explicit is not None:
        return explicit
    raw = os.getenv(env_name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{env_name} must be a boolean")


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    last = b""
    with path.open("rb") as fh:
        while block := fh.read(_TAIL_CHUNK):
            count += block.count(b"\n")
            last = block[-1:]
    return count + (1 if last and last != b"\n" else 0)


def _start_for_byte_budget(path: Path, budget: int) -> int:
    """Return a complete-line boundary retaining no more than ``budget`` bytes."""
    size = path.stat().st_size
    if budget <= 0:
        return size
    candidate = max(0, size - budget)
    if candidate == 0:
        return 0
    with path.open("rb") as fh:
        fh.seek(candidate - 1)
        if fh.read(1) == b"\n":
            return candidate
        fh.seek(candidate)
        position = candidate
        while position < size:
            block = fh.read(min(_TAIL_CHUNK, size - position))
            newline = block.find(b"\n")
            if newline >= 0:
                return position + newline + 1
            position += len(block)
        return size


def _start_for_line_budget(path: Path, limit: int) -> int:
    """Find the start of the newest ``limit`` lines using bounded blocks."""
    size = path.stat().st_size
    if limit <= 0 or size == 0:
        return size
    with path.open("rb") as fh:
        fh.seek(size - 1)
        trailing_newline = fh.read(1) == b"\n"
        needed = limit + (1 if trailing_newline else 0)
        seen = 0
        position = size
        while position > 0:
            read_size = min(_TAIL_CHUNK, position)
            position -= read_size
            fh.seek(position)
            block = fh.read(read_size)
            for index in range(len(block) - 1, -1, -1):
                if block[index] != 0x0A:
                    continue
                seen += 1
                if seen == needed:
                    return position + index + 1
    return 0


def _fsync_directory(path: Path) -> None:
    """Make an atomic retention rename durable on filesystems that support it."""
    if not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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


def _read_last_lines(path: Path, limit: int, max_bytes: int) -> list[str]:
    """Return up to ``limit`` trailing lines of ``path`` without loading it all.

    Seeks backwards from EOF in fixed-size blocks, accumulating until enough
    newline-separated lines are buffered. For typical ``tail`` limits this reads
    only the last few KB regardless of how large the file has grown.
    """
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        if end == 0:
            return []
        blocks: list[bytes] = []
        newline_count = 0
        total = 0
        pos = end
        # +1: a final line may not be newline-terminated, so we need one extra
        # newline boundary to be sure we captured ``limit`` complete lines.
        while pos > 0 and newline_count <= limit and (max_bytes <= 0 or total < max_bytes):
            remaining = max_bytes - total if max_bytes > 0 else _TAIL_CHUNK
            read_size = min(_TAIL_CHUNK, pos, remaining)
            if read_size <= 0:
                break
            pos -= read_size
            fh.seek(pos)
            block = fh.read(read_size)
            blocks.append(block)
            newline_count += block.count(b"\n")
            total += len(block)
    buffer = b"".join(reversed(blocks))
    text = buffer.decode("utf-8", "replace")
    lines = text.splitlines()
    if pos > 0 and lines:
        # The byte ceiling may start inside a record. Never parse or return that
        # partial oldest line.
        lines = lines[1:]
    return lines[-limit:] if limit < len(lines) else lines


class JsonlStore:
    """Append Pydantic models to a JSONL file, one per line.

    The store opens the file lazily on first write, so creating an
    instance pointed at a not-yet-existing path is cheap and safe.
    """

    def __init__(
        self,
        path: str | Path,
        max_bytes: int | None = None,
        max_lines: int | None = None,
        max_record_bytes: int | None = None,
        read_max_bytes: int | None = None,
        fsync: bool | None = None,
    ) -> None:
        self._path = Path(path)
        self._max_bytes = _nonnegative_limit(
            max_bytes,
            "ANALYZER_JSONL_MAX_BYTES",
            DEFAULT_MAX_BYTES,
        )
        self._max_lines = _nonnegative_limit(
            max_lines,
            "ANALYZER_JSONL_MAX_LINES",
            DEFAULT_MAX_LINES,
        )
        self._max_record_bytes = _nonnegative_limit(
            max_record_bytes,
            "ANALYZER_STORAGE_MAX_RECORD_BYTES",
            DEFAULT_MAX_RECORD_BYTES,
        )
        self._read_max_bytes = _nonnegative_limit(
            read_max_bytes,
            "ANALYZER_STORAGE_READ_MAX_BYTES",
            DEFAULT_READ_MAX_BYTES,
        )
        self._fsync = _bool_setting(fsync, "ANALYZER_JSONL_FSYNC", True)
        self._write_lock = threading.Lock()
        self._line_count: int | None = None

    @property
    def path(self) -> Path:
        """Filesystem path of the backing JSONL file."""
        return self._path

    def append(self, record: BaseModel) -> None:
        """Append one durable line without ever crossing configured hard caps.

        Old complete lines are atomically trimmed *before* the append. A record
        larger than the byte budget is rejected; retention failures also fail
        the request instead of acknowledging an unbounded file.
        """
        encoded = (record.model_dump_json() + "\n").encode("utf-8")
        record_limit = (
            min(limit for limit in (self._max_bytes, self._max_record_bytes) if limit > 0)
            if self._max_bytes or self._max_record_bytes
            else 0
        )
        if record_limit and len(encoded) > record_limit:
            raise StorageCapacityError(
                f"JSONL record ({len(encoded)} bytes) exceeds "
                f"the {record_limit}-byte storage budget"
            )
        with self._write_lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._trim_for_incoming(len(encoded))
            try:
                with self._path.open("ab") as fh:
                    # One O_APPEND write prevents line interleaving in the
                    # documented single-process writer model.
                    written = fh.write(encoded)
                    if written != len(encoded):
                        raise OSError("short JSONL append")
                    fh.flush()
                    if self._fsync:
                        os.fsync(fh.fileno())
            except OSError as exc:
                if exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", 122), errno.EFBIG}:
                    raise StorageCapacityError("JSONL storage is full") from exc
                raise
            if self._max_lines:
                self._line_count = (self._line_count or 0) + 1

    def _trim_for_incoming(self, incoming_bytes: int) -> None:
        if not self._path.exists():
            if self._max_lines:
                self._line_count = 0
            return
        if self._max_bytes <= 0 and self._max_lines <= 0:
            return
        size = self._path.stat().st_size
        byte_overflow = self._max_bytes > 0 and size + incoming_bytes > self._max_bytes
        # Roll down to a 50% low-water mark. Rewriting only at the hard ceiling
        # avoids an attacker forcing an O(cap) copy on every subsequent append.
        byte_budget = max(0, self._max_bytes // 2 - incoming_bytes) if byte_overflow else None
        line_budget = self._max_lines - 1 if self._max_lines else None
        current_lines = self._current_line_count() if line_budget is not None else None
        line_overflow = (
            line_budget is not None and current_lines is not None and current_lines > line_budget
        )
        if not byte_overflow and not line_overflow:
            return

        start = 0
        if byte_budget is not None and size > byte_budget:
            start = max(start, _start_for_byte_budget(self._path, byte_budget))
        if line_overflow and line_budget is not None:
            # The line cap uses the same low-water strategy as the byte cap.
            start = max(
                start,
                _start_for_line_budget(self._path, max(0, self._max_lines // 2 - 1)),
            )
        self._rewrite_from(start)
        self._line_count = _count_lines(self._path) if self._max_lines else None

    def _current_line_count(self) -> int:
        if self._line_count is None:
            self._line_count = _count_lines(self._path)
        return self._line_count

    def _rewrite_from(self, start: int) -> None:
        """Atomically retain bytes from a verified complete-line boundary."""
        if start <= 0:
            return
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w+b",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                suffix=".retention.tmp",
                delete=False,
            ) as target:
                temp_name = target.name
                with self._path.open("rb") as source:
                    source.seek(start)
                    shutil.copyfileobj(source, target, length=_TAIL_CHUNK)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temp_name, self._path)
            _fsync_directory(self._path.parent)
            temp_name = None
        except OSError as exc:
            raise StorageCapacityError(
                f"cannot enforce JSONL storage budget for {self._path}: {exc}"
            ) from exc
        finally:
            if temp_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temp_name)

    def tail(self, limit: int) -> list[dict]:
        """Return up to ``limit`` most recent records, newest first.

        Reads only the trailing region of the file (seeking backwards in blocks)
        rather than loading the whole file into memory. Blank/corrupt lines
        (e.g. a crash-truncated final record) are skipped, not fatal.
        """
        if limit <= 0 or not self._path.exists():
            return []
        recent = _read_last_lines(self._path, limit, self._read_max_bytes)
        return list(_parse_lines(reversed(recent)))

    def fingerprint(self) -> tuple[int, int]:
        """Cheap (line_count, file_size) snapshot of the store's current state.

        Mirrors :meth:`SqliteStore.fingerprint` so derived caches (attack-path
        prediction) can invalidate without reparsing every record. Append-only,
        so any write changes the byte size; line count guards the rare equal-size
        rewrite (retention trim). Counts bytes/newlines only — no JSON parsing.
        """
        if not self._path.exists():
            return (0, 0)
        line_count = 0
        with self._path.open("rb") as fh:
            while True:
                block = fh.read(_TAIL_CHUNK)
                if not block:
                    break
                line_count += block.count(b"\n")
        size = self._path.stat().st_size
        return (line_count, size)

    def find_one(self, field: str, value: str) -> dict | None:
        """Return the newest record whose top-level JSON field equals ``value``.

        Scans the WHOLE file (newest first) for parity with ``SqliteStore.find_one``,
        which queries the entire table — both backends must resolve the same id to the
        same record regardless of how many newer records exist.
        """
        if not self._path.exists():
            return None
        # Single forward pass keeping the last match: append-only means the newest
        # record with this id is the last matching line, so this resolves the same
        # record as a reverse scan without loading the whole file (+ a reversed
        # copy) into memory just to look up one id.
        match: dict | None = None
        with self._path.open(encoding="utf-8") as fh:
            for record in _parse_lines(fh):
                if record.get(field) == value:
                    match = record
        return match
