"""Alert lifecycle read model: de-duplicate occurrences and apply triage overlay.

The correlation engine appends a fresh ``Alert`` row per ``TraceBatch``, so a
persistent indicator produces many rows sharing one ``alert_key``. This module
collapses those into **one logical alert per key** — the newest occurrence
supplies the displayed fields, with ``occurrence_count`` / ``last_seen``
aggregated across the read window — and merges the latest triage ``AlertState``
(status / assignee / note / suppress) onto it.

Both are *read-time* overlays: the stored correlation Alerts are never mutated,
and the triage state lives in its own append-only store. De-duplication and
aggregation are bounded by the read window the caller passes — occurrences older
than the window are not folded in (the caller passes a generous window).
"""

from __future__ import annotations

from ..schemas import Alert


def occurrence_key(row: dict) -> str:
    """Grouping key for one stored alert row.

    The content-derived ``alert_key`` when present, else the per-occurrence
    ``alert_id`` so alerts persisted before ``alert_key`` existed still list
    (ungrouped, one logical alert each) rather than vanishing.
    """
    return row.get("alert_key") or row.get("alert_id") or ""


def latest_state_by_key(state_rows: list[dict]) -> dict[str, dict]:
    """Map ``alert_key`` to its newest ``AlertState`` row.

    ``state_rows`` are newest-first (as ``tail`` returns), so the first row seen
    for a key is the current state.
    """
    latest: dict[str, dict] = {}
    for row in state_rows:
        key = row.get("alert_key")
        if key and key not in latest:
            latest[key] = row
    return latest


def merge_alerts(
    alert_rows: list[dict],
    state_rows: list[dict],
    *,
    include_suppressed: bool = False,
) -> list[Alert]:
    """Collapse alert occurrences by ``alert_key`` and apply the triage overlay.

    ``alert_rows`` and ``state_rows`` are raw store records, newest-first. Returns
    one :class:`Alert` per key, built from its newest occurrence and enriched with
    ``occurrence_count`` / ``last_seen`` plus the latest triage state. Suppressed
    alerts are omitted unless ``include_suppressed``. Output keeps the input order
    (newest-occurrence first).
    """
    states = latest_state_by_key(state_rows)
    newest: dict[str, dict] = {}
    counts: dict[str, int] = {}
    last_seen: dict[str, str] = {}

    for row in alert_rows:  # newest-first
        key = occurrence_key(row)
        counts[key] = counts.get(key, 0) + 1
        if key not in newest:
            newest[key] = row  # first seen == newest occurrence
            created = row.get("created_at")
            if created is not None:
                last_seen[key] = created

    out: list[Alert] = []
    for key, row in newest.items():
        merged = dict(row)
        merged["occurrence_count"] = counts.get(key, 1)
        merged["last_seen"] = last_seen.get(key)
        state = states.get(key)
        if state is not None:
            merged["status"] = state.get("status", merged.get("status"))
            merged["assignee"] = state.get("assignee")
            merged["note"] = state.get("note")
            merged["suppressed"] = bool(state.get("suppressed", False))
            merged["updated_at"] = state.get("updated_at")
        alert = Alert.model_validate(merged)
        if alert.suppressed and not include_suppressed:
            continue
        out.append(alert)
    return out
