"""Bounded in-process cache for expensive report-detail projections."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from threading import RLock
from typing import Generic, TypeVar

from .. import metrics as metrics_mod

_T = TypeVar("_T")
StoreFingerprint = tuple[tuple[int, int], tuple[int, int]]

_HITS = "kcatta_report_projection_cache_hits_total"
_MISSES = "kcatta_report_projection_cache_misses_total"
_INVALIDATIONS = "kcatta_report_projection_cache_invalidations_total"
_EVICTIONS = "kcatta_report_projection_cache_evictions_total"
_SKIPPED = "kcatta_report_projection_cache_skipped_total"
_ENTRIES = "kcatta_report_projection_cache_entries"
_BYTES = "kcatta_report_projection_cache_bytes"
_MAX_ENTRIES = "kcatta_report_projection_cache_max_entries"
_MAX_BYTES = "kcatta_report_projection_cache_max_bytes"
_ENABLED = "kcatta_report_projection_cache_enabled"


@dataclass(frozen=True, slots=True)
class _CacheEntry(Generic[_T]):
    value: _T
    estimated_bytes: int
    fingerprint: StoreFingerprint


class ReportProjectionCache(Generic[_T]):
    """Thread-safe LRU bounded by both entry count and estimated memory.

    Each entry carries the combined fingerprint of its own asset/detection
    lineage. A new scan for another report therefore keeps hot pages cached,
    while an appended chunk or derived result for this report invalidates only
    its projection.
    """

    def __init__(self, *, max_entries: int, max_bytes: int) -> None:
        if max_entries < 0:
            raise ValueError("max_entries must be non-negative")
        if max_bytes < 0:
            raise ValueError("max_bytes must be non-negative")
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._entries: OrderedDict[str, _CacheEntry[_T]] = OrderedDict()
        self._estimated_bytes = 0
        self._lock = RLock()
        self._publish_gauges()

    @property
    def enabled(self) -> bool:
        return self._max_entries > 0 and self._max_bytes > 0

    def get(self, key: str, fingerprint: StoreFingerprint) -> _T | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                metrics_mod.inc(_MISSES)
                return None
            if entry.fingerprint != fingerprint:
                self._entries.pop(key)
                self._estimated_bytes -= entry.estimated_bytes
                metrics_mod.inc(_INVALIDATIONS)
                metrics_mod.inc(_MISSES)
                self._publish_gauges()
                return None
            self._entries.move_to_end(key)
            metrics_mod.inc(_HITS)
            return entry.value

    def put(
        self,
        key: str,
        fingerprint: StoreFingerprint,
        value: _T,
        *,
        estimated_bytes: int,
    ) -> bool:
        if estimated_bytes < 0:
            raise ValueError("estimated_bytes must be non-negative")
        with self._lock:
            if not self.enabled or estimated_bytes > self._max_bytes:
                metrics_mod.inc(_SKIPPED)
                return False

            previous = self._entries.pop(key, None)
            if previous is not None:
                self._estimated_bytes -= previous.estimated_bytes

            while self._entries and (
                len(self._entries) >= self._max_entries
                or self._estimated_bytes + estimated_bytes > self._max_bytes
            ):
                _, evicted = self._entries.popitem(last=False)
                self._estimated_bytes -= evicted.estimated_bytes
                metrics_mod.inc(_EVICTIONS)

            self._entries[key] = _CacheEntry(
                value=value,
                estimated_bytes=estimated_bytes,
                fingerprint=fingerprint,
            )
            self._estimated_bytes += estimated_bytes
            self._publish_gauges()
            return True

    def snapshot(self) -> tuple[int, int]:
        """Return current entry count and estimated bytes for tests/diagnostics."""
        with self._lock:
            return len(self._entries), self._estimated_bytes

    def _publish_gauges(self) -> None:
        metrics_mod.set_gauge(_ENTRIES, float(len(self._entries)))
        metrics_mod.set_gauge(_BYTES, float(self._estimated_bytes))
        metrics_mod.set_gauge(_MAX_ENTRIES, float(self._max_entries))
        metrics_mod.set_gauge(_MAX_BYTES, float(self._max_bytes))
        metrics_mod.set_gauge(_ENABLED, float(self.enabled))
