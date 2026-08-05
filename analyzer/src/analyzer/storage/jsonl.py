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
import hashlib
import heapq
import json
import logging
import os
import shutil
import tempfile
import threading
from collections.abc import Iterable, Iterator
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from .errors import StorageCapacityError, StorageCursorError
from .lineage import LineageKind, lineage_root

logger = logging.getLogger(__name__)

# Production-safe retention defaults (overridable via env). Explicit 0 disables
# a cap for deployments whose filesystem already enforces a stricter quota.
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_LINES = 0
DEFAULT_MAX_RECORD_BYTES = 12 * 1024 * 1024
DEFAULT_READ_MAX_BYTES = 32 * 1024 * 1024

# Block size used when reading the file tail backwards.
_TAIL_CHUNK = 64 * 1024


def _stored_timestamp(value: object) -> datetime | None:
    """Parse historical RFC3339 timestamps without relying on lexical order."""

    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _timestamp_us(value: datetime) -> int:
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    delta = normalized - datetime(1970, 1, 1, tzinfo=UTC)
    return (
        delta.days * 86_400 * 1_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )


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


def _reverse_lines(path: Path) -> Iterator[bytes]:
    """Yield complete physical lines newest-first with bounded block reads."""
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        position = fh.tell()
        remainder = b""
        while position > 0:
            read_size = min(_TAIL_CHUNK, position)
            position -= read_size
            fh.seek(position)
            parts = (fh.read(read_size) + remainder).split(b"\n")
            remainder = parts[0]
            for line in reversed(parts[1:]):
                if line:
                    yield line
        if remainder:
            yield remainder


def _reverse_lines_with_offsets(path: Path, end: int) -> Iterator[tuple[bytes, int]]:
    """Yield complete lines newest-first before ``end``, including byte offsets."""

    with path.open("rb") as fh:
        size = fh.seek(0, os.SEEK_END)
        position = min(max(0, end), size)
        remainder = b""
        while position > 0:
            read_size = min(_TAIL_CHUNK, position)
            position -= read_size
            fh.seek(position)
            data = fh.read(read_size) + remainder
            parts = data.split(b"\n")
            remainder = parts[0]
            starts: list[int] = []
            offset = position + len(parts[0]) + 1
            for part in parts[1:]:
                starts.append(offset)
                offset += len(part) + 1
            for part, start in reversed(tuple(zip(parts[1:], starts, strict=True))):
                if part:
                    yield part, start
        if remainder:
            yield remainder, 0


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
        self._value_indexes: dict[str, set[str]] = {}
        self._source_value_indexes: dict[
            str, set[tuple[str, str | None, str | None]]
        ] = {}

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
        encoded = self._encode_record(record)
        with self._write_lock:
            self._append_encoded_locked(encoded)
            self._update_indexes_locked(record.model_dump(mode="json"))

    def append_if_absent(
        self,
        field: str,
        value: str,
        record: BaseModel,
    ) -> bool:
        """Atomically append within the documented single-process model.

        Returns true only when a new row was written.  This closes the
        find-then-append race for deterministic derived alerts produced by two
        sibling chunk workers in the same process.
        """

        encoded = self._encode_record(record)
        with self._write_lock:
            values = self._indexed_values_locked(field)
            if value in values:
                return False
            self._append_encoded_locked(encoded)
            self._update_indexes_locked(record.model_dump(mode="json"))
        return True

    def append_many_if_absent(
        self,
        field: str,
        records: list[tuple[str, BaseModel]],
    ) -> set[str]:
        """Atomically retain one deterministic batch without stale-index loss."""

        prepared: dict[str, tuple[bytes, BaseModel]] = {}
        for value, record in records:
            prepared.setdefault(value, (self._encode_record(record), record))
        if not prepared:
            return set()
        prepared_bytes = sum(len(item[0]) for item in prepared.values())
        if self._max_lines and len(prepared) > self._max_lines:
            raise StorageCapacityError("JSONL batch exceeds the retained line budget")
        if self._max_bytes and prepared_bytes > self._max_bytes:
            raise StorageCapacityError("JSONL batch exceeds the retained byte budget")

        with self._write_lock:
            values = self._indexed_values_locked(field)
            missing = {
                value: item for value, item in prepared.items() if value not in values
            }
            if not missing:
                return set()
            current_size = self._path.stat().st_size if self._path.exists() else 0
            current_lines = self._current_line_count() if self._max_lines else 0
            missing_bytes = sum(len(item[0]) for item in missing.values())
            needs_rewrite = (
                (self._max_bytes > 0 and current_size + missing_bytes > self._max_bytes)
                or (
                    self._max_lines > 0
                    and current_lines + len(missing) > self._max_lines
                )
            )
            if needs_rewrite:
                # Refresh the whole requested set at the newest end of one
                # atomic retention rewrite. Otherwise an initially-present id
                # can be pruned by a later missing id and silently disappear.
                self._rewrite_with_batch_locked(field, prepared)
            else:
                payload = b"".join(item[0] for item in missing.values())
                self._append_batch_encoded_locked(payload, len(missing))
                for _encoded, record in missing.values():
                    self._update_indexes_locked(record.model_dump(mode="json"))
            inserted = set(missing)
        return inserted

    def _append_batch_encoded_locked(self, encoded: bytes, line_count: int) -> None:
        """Commit a no-retention batch in one write, rolling back a short write."""

        self._path.parent.mkdir(parents=True, exist_ok=True)
        original_size = self._path.stat().st_size if self._path.exists() else 0
        try:
            with self._path.open("a+b") as fh:
                written = fh.write(encoded)
                if written != len(encoded):
                    raise OSError("short JSONL batch append")
                fh.flush()
                if self._fsync:
                    os.fsync(fh.fileno())
        except OSError as exc:
            try:
                with self._path.open("r+b") as rollback:
                    rollback.truncate(original_size)
                    rollback.flush()
                    if self._fsync:
                        os.fsync(rollback.fileno())
            except OSError:
                logger.exception("could not roll back failed JSONL batch append")
            if exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", 122), errno.EFBIG}:
                raise StorageCapacityError("JSONL storage is full") from exc
            raise
        if self._max_lines:
            self._line_count = (self._line_count or 0) + line_count

    def _rewrite_with_batch_locked(
        self,
        field: str,
        prepared: dict[str, tuple[bytes, BaseModel]],
    ) -> None:
        """Atomically compact retention and refresh every requested batch id."""

        lines: list[bytes] = []
        if self._path.exists():
            with self._path.open("rb") as source:
                for raw in source:
                    if not raw.endswith(b"\n"):
                        continue
                    try:
                        record = json.loads(raw)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        lines.append(raw)
                        continue
                    if record.get(field) not in prepared:
                        lines.append(raw)
        lines.extend(item[0] for item in prepared.values())
        if self._max_lines:
            lines = lines[-self._max_lines :]
        if self._max_bytes:
            retained: list[bytes] = []
            retained_bytes = 0
            for raw in reversed(lines):
                if retained_bytes + len(raw) > self._max_bytes:
                    break
                retained.append(raw)
                retained_bytes += len(raw)
            lines = list(reversed(retained))

        self._path.parent.mkdir(parents=True, exist_ok=True)
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w+b",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                suffix=".batch.tmp",
                delete=False,
            ) as target:
                temp_name = target.name
                for raw in lines:
                    target.write(raw)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temp_name, self._path)
            _fsync_directory(self._path.parent)
            temp_name = None
        except OSError as exc:
            if exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", 122), errno.EFBIG}:
                raise StorageCapacityError("JSONL storage is full") from exc
            raise StorageCapacityError(f"cannot atomically commit JSONL batch: {exc}") from exc
        finally:
            if temp_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temp_name)

        indexed_fields = tuple(self._value_indexes)
        source_indexed_fields = tuple(self._source_value_indexes)
        self._value_indexes.clear()
        self._source_value_indexes.clear()
        for indexed_field in indexed_fields:
            self._indexed_values_locked(indexed_field)
        for indexed_field in source_indexed_fields:
            self._indexed_source_values_locked(indexed_field)
        self._line_count = len(lines) if self._max_lines else None

    def _update_indexes_locked(self, record: dict) -> None:
        for field, values in self._value_indexes.items():
            value = record.get(field)
            if isinstance(value, str):
                values.add(value)
        for field, values in self._source_value_indexes.items():
            value = record.get(field)
            if isinstance(value, str):
                values.add(
                    (
                        value,
                        record.get("source_agent_id"),
                        record.get("source_target_id"),
                    )
                )

    def _indexed_values_locked(self, field: str) -> set[str]:
        values = self._value_indexes.get(field)
        if values is not None:
            return values
        values = set()
        if self._path.exists():
            with self._path.open(encoding="utf-8") as fh:
                for item in _parse_lines(fh):
                    value = item.get(field)
                    if isinstance(value, str):
                        values.add(value)
        self._value_indexes[field] = values
        return values

    def _indexed_source_values_locked(
        self,
        field: str,
    ) -> set[tuple[str, str | None, str | None]]:
        values = self._source_value_indexes.get(field)
        if values is not None:
            return values
        values = set()
        if self._path.exists():
            with self._path.open(encoding="utf-8") as fh:
                for item in _parse_lines(fh):
                    value = item.get(field)
                    if isinstance(value, str):
                        values.add(
                            (
                                value,
                                item.get("source_agent_id"),
                                item.get("source_target_id"),
                            )
                        )
        self._source_value_indexes[field] = values
        return values

    def _encode_record(self, record: BaseModel) -> bytes:
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
        return encoded

    def _append_encoded_locked(self, encoded: bytes) -> None:
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
            indexed_fields = tuple(self._value_indexes)
            source_indexed_fields = tuple(self._source_value_indexes)
            self._value_indexes.clear()
            self._source_value_indexes.clear()
            for field in indexed_fields:
                self._indexed_values_locked(field)
            for field in source_indexed_fields:
                self._indexed_source_values_locked(field)
        except OSError as exc:
            raise StorageCapacityError(
                f"cannot enforce JSONL storage budget for {self._path}: {exc}"
            ) from exc
        finally:
            if temp_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temp_name)

    def tail(self, limit: int, offset: int = 0) -> list[dict]:
        """Return a stable newest-first page of retained records.

        Reads only the trailing region of the file (seeking backwards in blocks)
        rather than loading the whole file into memory. Blank/corrupt lines
        (e.g. a crash-truncated final record) are skipped, not fatal.

        ``offset`` counts valid records in newest-first order.  The default is
        backwards-compatible with the original ``tail(limit)`` API.
        """
        if limit <= 0 or offset < 0 or not self._path.exists():
            return []
        records: list[dict] = []
        valid_seen = 0
        returned_bytes = 0
        for raw in _reverse_lines(self._path):
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("skipping malformed JSONL line in store")
                continue
            if valid_seen < offset:
                valid_seen += 1
                continue
            if self._read_max_bytes and returned_bytes + len(raw) > self._read_max_bytes:
                break
            records.append(record)
            returned_bytes += len(raw)
            if len(records) >= limit:
                break
        return records

    def cursor_page(
        self,
        limit: int,
        anchor: str | None = None,
        *,
        field: str | None = None,
        value: str | None = None,
    ) -> tuple[list[dict], str | None, bool]:
        """Seek by physical line offset; concurrent appends cannot shift the cursor."""

        if limit <= 0:
            return [], None, False
        if (field is None) != (value is None):
            raise StorageCursorError("invalid cursor filter")
        if not self._path.exists():
            if anchor is not None:
                raise StorageCursorError("JSONL cursor snapshot is no longer retained")
            return [], None, False
        stat = self._path.stat()
        identity = f"{stat.st_dev:x}:{stat.st_ino:x}"
        end = stat.st_size
        if anchor is not None:
            try:
                device, inode, raw_end = anchor.split(":", 2)
                end = int(raw_end)
            except (ValueError, TypeError) as exc:
                raise StorageCursorError("invalid JSONL cursor anchor") from exc
            if f"{device}:{inode}" != identity or end < 0 or end > stat.st_size:
                raise StorageCursorError("JSONL cursor snapshot is no longer retained")

        records: list[dict] = []
        returned_bytes = 0
        last_start: int | None = None
        for raw, start in _reverse_lines_with_offsets(self._path, end):
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("skipping malformed JSONL line in store")
                continue
            if field is not None and record.get(field) != value:
                continue
            if self._read_max_bytes and returned_bytes + len(raw) > self._read_max_bytes:
                break
            records.append(record)
            returned_bytes += len(raw)
            last_start = start
            if len(records) >= limit:
                break
        if last_start is None:
            return [], None, False

        has_more = False
        for raw, _start in _reverse_lines_with_offsets(self._path, last_start):
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if field is None or record.get(field) == value:
                has_more = True
                break
        return records, f"{identity}:{last_start}", has_more

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

    def find_one_with_source(
        self,
        field: str,
        value: str,
        source_agent_id: str | None,
        source_target_id: str | None = None,
    ) -> dict | None:
        """Return the newest exact id in one authenticated provenance namespace."""

        if not self._path.exists():
            return None
        match: dict | None = None
        with self._path.open(encoding="utf-8") as fh:
            for record in _parse_lines(fh):
                if (
                    record.get(field) == value
                    and record.get("source_agent_id") == source_agent_id
                    and record.get("source_target_id") == source_target_id
                ):
                    match = record
        return match

    def contains_with_source(
        self,
        field: str,
        value: str,
        source_agent_id: str | None,
        source_target_id: str | None = None,
    ) -> bool:
        """Use one bounded retained-record index for source-scoped retry checks."""

        with self._write_lock:
            return (
                value,
                source_agent_id,
                source_target_id,
            ) in self._indexed_source_values_locked(field)

    def find_lineage(
        self,
        field: str,
        value: str,
        kind: LineageKind,
        *,
        source_agent_id: str | None = None,
        source_target_id: str | None = None,
        filter_provenance: bool = False,
    ) -> list[dict]:
        """Return matching lineage rows in one reverse pass over the JSONL file."""
        if not self._path.exists():
            return []
        root = lineage_root(value, kind)
        records: list[dict] = []
        for raw in _reverse_lines(self._path):
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("skipping malformed JSONL line in lineage lookup")
                continue
            record_id = record.get(field)
            if (
                isinstance(record_id, str)
                and lineage_root(record_id, kind) == root
                and (
                    not filter_provenance
                    or (
                        record.get("source_agent_id") == source_agent_id
                        and record.get("source_target_id") == source_target_id
                    )
                )
            ):
                records.append(record)
        return records

    def find_lineage_bounded(
        self,
        field: str,
        value: str,
        kind: LineageKind,
        *,
        source_agent_id: str | None = None,
        source_target_id: str | None = None,
        filter_provenance: bool = False,
    ) -> tuple[list[dict], bool]:
        """Return one lineage without exceeding the configured read budget."""

        if not self._path.exists():
            return [], False
        root = lineage_root(value, kind)
        records: list[dict] = []
        consumed = 0
        scanned = 0
        for raw in _reverse_lines(self._path):
            if not filter_provenance:
                scanned += len(raw) + 1
                if self._read_max_bytes and scanned > self._read_max_bytes:
                    return records, True
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("skipping malformed JSONL line in lineage lookup")
                continue
            record_id = record.get(field)
            if (
                not isinstance(record_id, str)
                or lineage_root(record_id, kind) != root
                or (
                    filter_provenance
                    and (
                        record.get("source_agent_id") != source_agent_id
                        or record.get("source_target_id") != source_target_id
                    )
                )
            ):
                continue
            if filter_provenance:
                scanned += len(raw) + 1
                if self._read_max_bytes and scanned > self._read_max_bytes:
                    return records, True
            if self._read_max_bytes and consumed + len(raw) > self._read_max_bytes:
                return records, True
            records.append(record)
            consumed += len(raw)
        return records, False

    def find_asset_reports_before(
        self,
        *,
        host_id: str,
        before: datetime,
        source_agent_id: str | None,
        source_target_id: str | None,
    ) -> tuple[list[dict], datetime | None]:
        """Return retained reports for one provenanced host before a timestamp.

        Unrelated hosts do not consume the read budget.  The second result is
        the newest timestamp omitted by that budget.  Callers may safely use a
        complete baseline newer than the cutoff, while an equal/newer omission
        must fail closed.
        """

        if not self._path.exists():
            return [], None
        normalized_before = (
            before.replace(tzinfo=UTC) if before.tzinfo is None else before.astimezone(UTC)
        )
        # Keep only the newest matching records under the return-byte budget.
        # JSONL insertion order is not assumed to equal collection time: a
        # delayed upload with an older timestamp must not displace a newer
        # baseline merely because it was appended last.
        retained: list[tuple[datetime, int, int, dict]] = []
        retained_bytes = 0
        newest_omitted: datetime | None = None
        sequence = 0
        scanned = 0
        for raw in _reverse_lines(self._path):
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("skipping malformed JSONL line in asset baseline lookup")
                continue
            host = record.get("host")
            collected_at = _stored_timestamp(record.get("collected_at"))
            if (
                not isinstance(host, dict)
                or host.get("host_id") != host_id
                or collected_at is None
                or collected_at >= normalized_before
                or record.get("source_agent_id") != source_agent_id
                or record.get("source_target_id") != source_target_id
            ):
                continue
            scanned += len(raw) + 1
            if self._read_max_bytes and scanned > self._read_max_bytes:
                newest_omitted = datetime.max.replace(tzinfo=UTC)
                break
            sequence += 1
            heapq.heappush(retained, (collected_at, sequence, len(raw), record))
            retained_bytes += len(raw)
            while self._read_max_bytes and retained_bytes > self._read_max_bytes:
                omitted_at, _order, omitted_bytes, _record = heapq.heappop(retained)
                retained_bytes -= omitted_bytes
                if newest_omitted is None or omitted_at > newest_omitted:
                    newest_omitted = omitted_at
        ordered = sorted(retained, key=lambda item: (item[0], item[1]), reverse=True)
        return [item[3] for item in ordered], newest_omitted

    def find_asset_reports_after(
        self,
        *,
        host_id: str,
        after: datetime,
        source_agent_id: str | None,
        source_target_id: str | None,
    ) -> tuple[list[dict], datetime | None]:
        """Return the oldest retained reports after one provenanced snapshot."""

        if not self._path.exists():
            return [], None
        normalized_after = (
            after.replace(tzinfo=UTC) if after.tzinfo is None else after.astimezone(UTC)
        )
        # A negative exact-microsecond key makes heapq evict the newest item,
        # retaining the adjacent future history regardless of arrival order.
        retained: list[tuple[int, int, datetime, int, dict]] = []
        retained_bytes = 0
        oldest_omitted: datetime | None = None
        sequence = 0
        scanned = 0
        for raw in _reverse_lines(self._path):
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("skipping malformed JSONL line in asset forward lookup")
                continue
            host = record.get("host")
            collected_at = _stored_timestamp(record.get("collected_at"))
            if (
                not isinstance(host, dict)
                or host.get("host_id") != host_id
                or collected_at is None
                or collected_at <= normalized_after
                or record.get("source_agent_id") != source_agent_id
                or record.get("source_target_id") != source_target_id
            ):
                continue
            scanned += len(raw) + 1
            if self._read_max_bytes and scanned > self._read_max_bytes:
                oldest_omitted = datetime.min.replace(tzinfo=UTC)
                break
            sequence += 1
            heapq.heappush(
                retained,
                (-_timestamp_us(collected_at), sequence, collected_at, len(raw), record),
            )
            retained_bytes += len(raw)
            while self._read_max_bytes and retained_bytes > self._read_max_bytes:
                _key, _order, omitted_at, omitted_bytes, _record = heapq.heappop(retained)
                retained_bytes -= omitted_bytes
                if oldest_omitted is None or omitted_at < oldest_omitted:
                    oldest_omitted = omitted_at
        ordered = sorted(retained, key=lambda item: (item[2], item[1]))
        return [item[4] for item in ordered], oldest_omitted

    def lineage_fingerprint(
        self,
        field: str,
        value: str,
        kind: LineageKind,
    ) -> tuple[int, int]:
        """Return a content fingerprint for one logical lineage only.

        Unrelated appends do not alter the digest. Hashing matching raw records
        also detects retention rewrites, replacement, and duplicate ordering;
        this is more precise than physical offsets or the whole-file size.
        """
        if not self._path.exists():
            return (0, 0)
        root = lineage_root(value, kind)
        digest = hashlib.blake2b(digest_size=16)
        count = 0
        for raw in _reverse_lines(self._path):
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            record_id = record.get(field)
            if isinstance(record_id, str) and lineage_root(record_id, kind) == root:
                digest.update(raw)
                digest.update(b"\n")
                count += 1
        return (count, int.from_bytes(digest.digest(), "big")) if count else (0, 0)
