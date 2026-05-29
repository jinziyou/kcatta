"""Ingest endpoints for scanner and collector uploads."""

from __future__ import annotations

import sys

from fastapi import APIRouter, Request, status
from pydantic import BaseModel
from starlette.datastructures import State

from ..detect import detect_report, resolve_ecosystem
from ..schemas import AssetReport, DetectionResult, FlowBatch

router = APIRouter(prefix="/ingest", tags=["ingest"])


class IngestAck(BaseModel):
    """Returned to upstream agents after a successful ingest.

    `accepted` is redundant given the 202 status code but lets clients
    avoid status-code parsing in shell pipelines.
    """

    accepted: bool = True
    id: str


@router.post(
    "/asset-report",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_asset_report(report: AssetReport, request: Request) -> IngestAck:
    request.app.state.asset_report_store.append(report)
    _auto_detect(report, request.app.state)
    return IngestAck(id=report.report_id)


def _auto_detect(report: AssetReport, state: State) -> None:
    """Best-effort: run detection and persist a DetectionResult.

    Skips silently when no OSV data is loaded or the ecosystem can't be
    resolved, and never lets a detection error fail the ingest (the report
    is already safely stored).
    """
    store = state.osv_store
    if store.record_count == 0:
        return
    ecosystem = resolve_ecosystem(report, state.osv_ecosystem)
    if not ecosystem:
        return
    try:
        vulnerabilities = detect_report(report, store, ecosystem)
    except Exception as exc:  # noqa: BLE001 - detection must never break ingest
        print(f"detection failed for {report.report_id}: {exc}", file=sys.stderr)
        return
    state.vulnerability_store.append(
        DetectionResult(
            report_id=report.report_id,
            host_id=report.host.host_id,
            collected_at=report.collected_at,
            ecosystem=ecosystem,
            vulnerabilities=vulnerabilities,
        )
    )


@router.post(
    "/flow-batch",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_flow_batch(batch: FlowBatch, request: Request) -> IngestAck:
    request.app.state.flow_batch_store.append(batch)
    return IngestAck(id=batch.batch_id)
