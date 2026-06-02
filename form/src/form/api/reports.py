"""Read-side endpoints over the JSONL ingest stores.

These are intentionally raw: each endpoint returns the latest N stored
records, newest first. Higher-level views (per-host, per-severity,
joins between assets and flows) belong in `form.api.assets` /
`form.api.alerts` once normalization lands.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, status

from ..schemas import Alert, AssetReport, DetectionResult, FlowBatch

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/asset-reports", response_model=list[AssetReport])
async def list_asset_reports(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    return request.app.state.asset_report_store.tail(limit)


@router.get("/asset-reports/{report_id}", response_model=AssetReport)
async def get_asset_report(report_id: str, request: Request) -> dict:
    record = request.app.state.asset_report_store.find_one("report_id", report_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    return record


@router.get("/flow-batches", response_model=list[FlowBatch])
async def list_flow_batches(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    return request.app.state.flow_batch_store.tail(limit)


@router.get("/vulnerabilities", response_model=list[DetectionResult])
async def list_vulnerabilities(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    return request.app.state.vulnerability_store.tail(limit)


@router.get("/alerts", response_model=list[Alert])
async def list_alerts(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    return request.app.state.alert_store.tail(limit)


@router.get("/alerts/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str, request: Request) -> dict:
    record = request.app.state.alert_store.find_one("alert_id", alert_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    return record
