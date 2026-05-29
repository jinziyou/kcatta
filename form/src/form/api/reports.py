"""Read-side endpoints over the JSONL ingest stores.

These are intentionally raw: each endpoint returns the latest N stored
records, newest first. Higher-level views (per-host, per-severity,
joins between assets and flows) belong in `form.api.assets` /
`form.api.alerts` once normalization lands.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from ..schemas import AssetReport, DetectionResult, FlowBatch

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/asset-reports", response_model=list[AssetReport])
async def list_asset_reports(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    return request.app.state.asset_report_store.tail(limit)


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
