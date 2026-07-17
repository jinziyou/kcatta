"""Alert read + triage endpoints.

Reads collapse the per-batch alert occurrences into one logical alert per
``alert_key`` (de-duplicated, with ``occurrence_count`` / ``last_seen``) and
overlay the latest triage state. The single write path — triage — appends an
``AlertState`` snapshot (status / assignee / note / suppress). CORS allows only
GET/POST, so triage is a POST, not a PATCH.
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import UTC, datetime
from itertools import islice

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from ..correlate.lifecycle import append_related_evidence, merge_alerts, occurrence_key
from ..schemas import Alert, AlertState, AlertStatus, AlertTriageRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports/alerts", tags=["alerts"])

# The CSV export targets completeness (a SIEM dump), not the paged JSON view, so it
# scans a much larger slice of occurrences; if even this cap is reached the
# response discloses it via an `X-Alert-Export-Truncated` header.
ALERT_EXPORT_WINDOW = 50_000
STORE_PAGE_SIZE = 500


def _alert_rows_for_key(request: Request, alert_key: str) -> list[dict]:
    """Every retained occurrence whose logical identity equals ``alert_key``."""
    return [
        row
        for row in _retained_rows(request.app.state.alert_store)
        if occurrence_key(row) == alert_key
    ]


def _state_rows(request: Request) -> list[dict]:
    """Newest retained triage snapshot for every logical alert."""
    return list(_latest_retained_states(request).values())


def _retained_rows(store):  # type: ignore[no-untyped-def]
    """Iterate every retained record newest-first without one huge read."""
    offset = 0
    while True:
        page = store.tail(STORE_PAGE_SIZE, offset)
        if not page:
            return
        yield from page
        offset += len(page)


def _latest_retained_states(request: Request) -> dict[str, dict]:
    """Newest triage snapshot per key across the retained state store."""
    states: dict[str, dict] = {}
    for row in _retained_rows(request.app.state.alert_state_store):
        key = row.get("alert_key")
        if key and key not in states:
            states[key] = row
    return states


def _page_logical_alerts(
    request: Request,
    *,
    limit: int,
    offset: int,
    include_suppressed: bool,
) -> list[Alert]:
    """Page logical alert keys while aggregating all retained occurrences.

    Pagination is over de-duplicated alerts, not raw occurrence rows. Discovery
    follows each key's newest occurrence (the store's stable insertion order),
    then the remainder of the retained store is scanned to produce an honest
    occurrence count for the selected page.
    """
    states = _latest_retained_states(request)
    selected: dict[str, dict] = {}
    counts: dict[str, int] = {}
    related: dict[str, dict[str, list[str]]] = {}
    evidence_truncated: set[str] = set()
    seen: set[str] = set()
    visible_index = 0
    selection_complete = False

    for row in _retained_rows(request.app.state.alert_store):
        key = occurrence_key(row)
        if key in selected:
            counts[key] += 1
            append_related_evidence(related, evidence_truncated, key, row)
            continue
        if selection_complete or key in seen:
            continue
        seen.add(key)
        state = states.get(key)
        suppressed = bool(state and state.get("suppressed", False))
        if suppressed and not include_suppressed:
            continue
        if visible_index >= offset:
            selected[key] = row
            counts[key] = 1
            append_related_evidence(related, evidence_truncated, key, row)
            if len(selected) >= limit:
                selection_complete = True
        visible_index += 1

    if not selected:
        return []
    selected_states = [states[key] for key in selected if key in states]
    merged = merge_alerts(
        list(selected.values()),
        selected_states,
        include_suppressed=True,
    )
    return [
        alert.model_copy(
            update={
                "occurrence_count": counts.get(alert.alert_key or alert.alert_id, 1),
                **related.get(alert.alert_key or alert.alert_id, {}),
                "evidence_truncated": (alert.alert_key or alert.alert_id) in evidence_truncated,
            }
        )
        for alert in merged
    ]


@router.get("", response_model=list[Alert])
async def list_alerts(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    include_suppressed: bool = Query(default=False, description="include suppressed alerts"),
) -> list[Alert]:
    """List correlated alerts, de-duplicated by ``alert_key``, newest first.

    Each entry is one logical alert (its newest occurrence) carrying
    ``occurrence_count`` / ``last_seen`` and the latest triage state. Suppressed
    alerts are hidden unless ``include_suppressed=true``.
    """
    return _page_logical_alerts(
        request,
        limit=limit,
        offset=offset,
        include_suppressed=include_suppressed,
    )


_CSV_COLUMNS = [
    "alert_id",
    "alert_key",
    "severity",
    "status",
    "score",
    "title",
    "description",
    "related_asset_ids",
    "related_vuln_ids",
    "related_trace_ids",
    "evidence_truncated",
    "assignee",
    "note",
    "suppressed",
    "occurrence_count",
    "last_seen",
    "created_at",
    "updated_at",
]

# Characters that make a spreadsheet (Excel / Sheets / LibreOffice) treat a cell
# as a FORMULA. Alert fields carry attacker-influenced data (IOC indicators,
# hostnames, file paths), so an exported cell beginning with one of these must be
# neutralized — otherwise opening the CSV can execute injected formulas.
_CSV_INJECT_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    """Prefix a `'` so a formula-looking cell renders as literal text.

    Guards more than the first character: a spreadsheet renders an embedded
    newline as an in-cell line and will execute a formula on *any* such line, and
    leading whitespace before a formula char is also a known bypass — so a quote
    is prefixed if ANY line, ignoring leading whitespace, begins with a dangerous
    char. (csv quoting keeps the cell one field but does not stop formula
    execution; the lstrip check makes this independent of model whitespace
    stripping.)"""
    for line in value.splitlines() or [value]:
        if line.lstrip()[:1] in _CSV_INJECT_PREFIXES:
            return "'" + value
    return value


def _csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        # Neutralize EACH element before joining: an analyst who splits the cell on
        # ';' (the documented delimiter) would otherwise land a 2nd+ element such as
        # `=cmd|...` in a cell as a live formula.
        return ";".join(_csv_safe(str(v)) for v in value)
    return str(value)


def _alert_csv_row(a: Alert) -> list[str]:
    return [
        _csv_safe(_csv_cell(v))
        for v in (
            a.alert_id,
            a.alert_key,
            a.severity,
            a.status,
            a.score,
            a.title,
            a.description,
            a.related_asset_ids,
            a.related_vuln_ids,
            a.related_trace_ids,
            a.evidence_truncated,
            a.assignee,
            a.note,
            a.suppressed,
            a.occurrence_count,
            a.last_seen,
            a.created_at,
            a.updated_at,
        )
    ]


@router.get("/export.csv")
async def export_alerts_csv(
    request: Request,
    include_suppressed: bool = Query(default=False, description="include suppressed alerts"),
) -> Response:
    """Export the de-duplicated alerts as CSV for SIEM / spreadsheet ingest.

    Same read model as the JSON list endpoint (dedup by ``alert_key`` with
    ``occurrence_count`` / ``last_seen`` and the latest triage overlay). Cells are
    quoted by the csv writer and formula-injection-neutralized.

    Scans up to ``ALERT_EXPORT_WINDOW`` recent occurrences; if retained history
    exceeds that cap (so older occurrences are not included) the response carries
    ``X-Alert-Export-Truncated: true``.
    """
    sampled = list(islice(_retained_rows(request.app.state.alert_store), ALERT_EXPORT_WINDOW + 1))
    export_truncated = len(sampled) > ALERT_EXPORT_WINDOW
    window = sampled[:ALERT_EXPORT_WINDOW]
    merged = merge_alerts(window, _state_rows(request), include_suppressed=include_suppressed)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUMNS)
    for a in merged:
        writer.writerow(_alert_csv_row(a))
    headers = {"Content-Disposition": 'attachment; filename="alerts.csv"'}
    if export_truncated:
        headers["X-Alert-Export-Truncated"] = "true"
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )


@router.get("/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str, request: Request) -> Alert:
    """Fetch one logical alert by any of its occurrence ids (``alert_id``).

    Resolves the occurrence, derives its ``alert_key``, then returns the merged
    logical alert (aggregated + triage overlay). Suppressed alerts are still
    viewable here so they can be un-suppressed.
    """
    anchor = request.app.state.alert_store.find_one("alert_id", alert_id)
    if anchor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    key = occurrence_key(anchor)
    rows = _alert_rows_for_key(request, key) or [anchor]
    merged = merge_alerts(rows, _state_rows(request), include_suppressed=True)
    # Exactly one key in ``rows`` → exactly one merged alert.
    return merged[0]


@router.post("/{alert_key}/triage", response_model=Alert)
async def triage_alert(alert_key: str, body: AlertTriageRequest, request: Request) -> Alert:
    """Apply a triage update to the alert identified by ``alert_key``.

    Reads the current triage snapshot, applies the partial update (``None`` means
    leave unchanged), and appends a new full ``AlertState`` snapshot — so the
    current state is always a single newest-record lookup. Returns the merged
    logical alert reflecting the update.
    """
    alert_store = request.app.state.alert_store
    state_store = request.app.state.alert_state_store

    # The alert_key must correspond to a real alert (new keys or legacy alert_ids).
    anchor = alert_store.find_one("alert_key", alert_key) or alert_store.find_one(
        "alert_id", alert_key
    )
    if anchor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown alert_key")

    current = state_store.find_one("alert_key", alert_key)
    snapshot = _next_snapshot(alert_key, body, current, _actor(request))
    state_store.append(snapshot)

    rows = _alert_rows_for_key(request, alert_key) or [anchor]
    merged = merge_alerts(rows, _state_rows(request), include_suppressed=True)
    return merged[0]


def _next_snapshot(
    alert_key: str,
    body: AlertTriageRequest,
    current: dict | None,
    actor: str,
) -> AlertState:
    """Fold a partial triage update onto the current snapshot into a new snapshot.

    ``None`` fields inherit the current value (or a sane default); the request
    validator guarantees at least one field is set.
    """

    def _prev(field: str, default):  # type: ignore[no-untyped-def]
        return current.get(field) if current else default

    status_value = body.status or _prev("status", AlertStatus.OPEN)
    assignee = body.assignee if body.assignee is not None else _prev("assignee", None)
    note = body.note if body.note is not None else _prev("note", None)
    suppressed = (
        body.suppressed if body.suppressed is not None else bool(_prev("suppressed", False))
    )
    return AlertState(
        alert_key=alert_key,
        status=AlertStatus(status_value),
        assignee=assignee,
        note=note,
        suppressed=suppressed,
        actor=actor,
        updated_at=datetime.now(UTC),
    )


def _actor(request: Request) -> str:
    """Best-effort triage actor. Honest under shared-token auth: there is no real
    principal yet (see the identity-layer roadmap item), so record the optional
    ``X-Actor`` header or a ``shared-token`` placeholder."""
    header = request.headers.get("x-actor")
    return header.strip() if header and header.strip() else "shared-token"
