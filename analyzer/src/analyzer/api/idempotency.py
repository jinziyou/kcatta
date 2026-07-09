"""Bounded idempotency tracking for ingest endpoints.

Agent uploads retry on transient failures (5xx, timeouts, a brief analyzer
restart). Without deduplication, a retry of a request the analyzer already
processed — but whose ``202`` the agent never saw — lands a *second* copy of the
same envelope, producing duplicate rows that inflate counts and needlessly
re-run detection / correlation.

Every uplink envelope already carries a stable unique id (``report_id`` /
``batch_id``), so we dedupe on that: the first delivery is processed and the id
remembered; a later delivery with the same id is acknowledged with the same
``202`` but not re-stored. No contract change is required.

The remembered-id set is **bounded** (FIFO eviction) and **in-memory**: it is a
best-effort guard against the common retry storm, not a durable exactly-once
ledger. Under multiple worker processes each worker keeps its own set, so an id
seen first by another worker — or evicted past the window during a long outage —
may still be stored twice. This pairs with the agent-side durable spool (which
re-sends after an outage): together they make duplicates *rare*, not impossible.
"""

from __future__ import annotations

import threading
from collections import OrderedDict

DEFAULT_WINDOW = 50_000


class SeenIds:
    """Thread-safe bounded FIFO set of recently-seen ingest ids."""

    def __init__(self, maxlen: int = DEFAULT_WINDOW) -> None:
        self._maxlen = max(1, maxlen)
        # Ordered by insertion; oldest at the front for O(1) FIFO eviction.
        self._ids: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def check_and_add(self, key: str) -> bool:
        """Record ``key`` and report whether it was already present.

        Returns ``True`` if ``key`` was seen before (i.e. this is a duplicate),
        ``False`` on first sight. The test-and-set is atomic so two concurrent
        retries of the same id can never both observe a miss.
        """
        with self._lock:
            if key in self._ids:
                # Refresh recency so an id still being retried isn't evicted
                # mid-storm and then treated as fresh.
                self._ids.move_to_end(key)
                return True
            self._ids[key] = None
            if len(self._ids) > self._maxlen:
                self._ids.popitem(last=False)
            return False

    def discard(self, key: str) -> None:
        """Undo a prior ``check_and_add`` reservation for ``key``.

        Callers reserve an id *before* the durable store; if that store then
        fails they must ``discard`` the id so the agent's retry is processed
        rather than silently deduped into permanent data loss.
        """
        with self._lock:
            self._ids.pop(key, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._ids)
