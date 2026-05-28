"""Ingest endpoints for scanner and collector uploads."""

from __future__ import annotations

from fastapi import APIRouter, Request, status
from pydantic import BaseModel

from ..schemas import AssetReport, FlowBatch

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
    return IngestAck(id=report.report_id)


@router.post(
    "/flow-batch",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_flow_batch(batch: FlowBatch, request: Request) -> IngestAck:
    request.app.state.flow_batch_store.append(batch)
    return IngestAck(id=batch.batch_id)
