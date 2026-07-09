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

import json
import logging
import os
from collections.abc import Iterable, Iterator
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Retention defaults (overridable via env). 0 / unset disables that cap.
_DEFAULT_MAX_BYTES = int(os.getenv("ANALYZER_JSONL_MAX_BYTES", "0") or "0")
_DEFAULT_MAX_LINES = int(os.getenv("ANALYZER_JSONL_MAX_LINES", "0") or "0")

# Block size used when reading the file tail backwards.
_TAIL_CHUNK = 64 * 1024


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


def _read_last_lines(path: Path, limit: int) -> list[str]:
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
        buffer = b""
        pos = end
        # +1: a final line may not be newline-terminated, so we need one extra
        # newline boundary to be sure we captured ``limit`` complete lines.
        while pos > 0 and buffer.count(b"\n") <= limit:
            read_size = min(_TAIL_CHUNK, pos)
            pos -= read_size
            fh.seek(pos)
            buffer = fh.read(read_size) + buffer
    text = buffer.decode("utf-8", "replace")
    lines = text.splitlines()
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
    ) -> None:
        self._path = Path(path)
        self._max_bytes = _DEFAULT_MAX_BYTES if max_bytes is None else max_bytes
        self._max_lines = _DEFAULT_MAX_LINES if max_lines is None else max_lines

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
        self._enforce_retention()

    def _enforce_retention(self) -> None:
        """Trim the file to the newest records when a size/line cap is exceeded.

        Best-effort: keeps the most recent records (what ``tail`` serves) and
        drops the oldest. Disabled when both caps are 0.
        """
        if self._max_bytes <= 0 and self._max_lines <= 0:
            return
        try:
            over_size = self._max_bytes > 0 and self._path.stat().st_size > self._max_bytes
            if not over_size and self._max_lines <= 0:
                return
            # Keep at most max_lines (or, when only a byte cap is set, keep the
            # tail that fits; approximate by keeping the last max_lines or 10k).
            keep = self._max_lines if self._max_lines > 0 else 10_000
            with self._path.open(encoding="utf-8") as fh:
                lines = fh.readlines()
            if len(lines) <= keep and not over_size:
                return
            kept = lines[-keep:]
            tmp = self._path.with_name(self._path.name + ".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                fh.writelines(kept)
                fh.flush()
            tmp.replace(self._path)
        except OSError as exc:  # retention is best-effort; never fail an append
            logger.warning("JSONL retention trim failed for %s: %s", self._path, exc)

    def tail(self, limit: int) -> list[dict]:
        """Return up to ``limit`` most recent records, newest first.

        Reads only the trailing region of the file (seeking backwards in blocks)
        rather than loading the whole file into memory. Blank/corrupt lines
        (e.g. a crash-truncated final record) are skipped, not fatal.
        """
        if limit <= 0 or not self._path.exists():
            return []
        recent = _read_last_lines(self._path, limit)
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
