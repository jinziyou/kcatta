"""Read-side endpoints over the ingest record stores (JSONL or SQLite,
per ``ANALYZER_STORAGE``).

These are intentionally raw: each endpoint tails its store for the latest
N records, newest first, or fetches a single record by id. Aggregated
views (per-host, per-severity, joins between assets and events) are future
work, pending normalization.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, status

from ..schemas import AssetReport, DetectionResult, GuardEventBatch, TraceBatch

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/asset-reports", response_model=list[AssetReport])
async def list_asset_reports(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    """List the most recent ingested asset reports, newest first."""
    return request.app.state.asset_report_store.tail(limit)


@router.get("/asset-reports/{report_id}", response_model=AssetReport)
async def get_asset_report(report_id: str, request: Request) -> dict:
    """Fetch a single ingested asset report by its report ID."""
    record = request.app.state.asset_report_store.find_one("report_id", report_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    return record


@router.get("/trace-batches", response_model=list[TraceBatch])
async def list_trace_batches(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    """List the most recent ingested network trace batches, newest first."""
    return request.app.state.trace_batch_store.tail(limit)


@router.get("/vulnerabilities", response_model=list[DetectionResult])
async def list_vulnerabilities(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    """List the most recent detection results (vulnerability findings), newest first."""
    return request.app.state.vulnerability_store.tail(limit)


@router.get("/vulnerabilities/{report_id}", response_model=DetectionResult)
async def get_report_detections(report_id: str, request: Request) -> dict:
    """Fetch the detection result for a single asset report (by its report ID)."""
    record = request.app.state.vulnerability_store.find_one("report_id", report_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no detections for report"
        )
    return record


@router.get("/guard-events", response_model=list[GuardEventBatch])
async def list_guard_events(
    request: Request,
    host_id: str | None = Query(default=None, description="filter to one host"),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    """List the most recent real-time protection event batches, newest first.

    Optionally filter to a single ``host_id`` (e.g. the host a guard scan targets).
    """
    if host_id is None:
        return request.app.state.guard_event_store.tail(limit)
    recent = request.app.state.guard_event_store.tail(500)
    return [record for record in recent if record.get("host_id") == host_id][:limit]
