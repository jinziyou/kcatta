"""Ingest endpoints for scanner and collector uploads."""

from __future__ import annotations

import sys

from fastapi import APIRouter, Request, status
from pydantic import BaseModel
from starlette.datastructures import State

from ..correlate import correlate_flow_batch, cross_source_alerts
from ..detect import combine_findings, detect_report, resolve_ecosystem, scanner_findings
from ..schemas import AssetReport, CapabilityGraph, DetectionResult, FlowBatch

router = APIRouter(prefix="/ingest", tags=["ingest"])

# How many recent DetectionResults the cross-source correlation scans for
# high/critical vulnerable hosts. Bounded so correlation stays cheap; a host
# whose detection has aged out of this window won't get a cross-source alert.
CROSS_SOURCE_WINDOW = 500


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
    """Store an uploaded asset report and run best-effort vulnerability detection."""
    request.app.state.asset_report_store.append(report)
    _auto_detect(report, request.app.state)
    return IngestAck(id=report.report_id)


def _auto_detect(report: AssetReport, state: State) -> None:
    """Best-effort: run OSV detection, merge scanner findings, persist.

    Skips when there are no findings. Never lets a detection error fail the
    ingest (the report is already safely stored).
    """
    malware = scanner_findings(report)
    osv_vulns: list = []
    ecosystem = resolve_ecosystem(report, state.osv_ecosystem) or ""

    store = state.osv_store
    if store.record_count > 0 and ecosystem:
        try:
            osv_vulns = detect_report(report, store, ecosystem)
        except Exception as exc:  # noqa: BLE001 - detection must never break ingest
            print(f"detection failed for {report.report_id}: {exc}", file=sys.stderr)

    vulnerabilities = combine_findings(osv_vulns, malware)
    if not vulnerabilities:
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
    """Store an uploaded network flow batch and run best-effort alert correlation."""
    request.app.state.flow_batch_store.append(batch)
    _correlate(batch, request.app.state)
    return IngestAck(id=batch.batch_id)


def _correlate(batch: FlowBatch, state: State) -> None:
    """Best-effort: derive alerts from flow threat-intel hits, persist.

    Never lets a correlation error fail the ingest (the batch is already
    safely stored). The pure IOC alerts are persisted first and unconditionally;
    only the cross-source enrichment (which reads historical detections) is
    allowed to degrade on bad/aged data — it must not drop the IOC alerts.
    """
    # 1. IOC alerts are a pure function of the batch — compute and persist first
    #    so a later cross-source failure can never lose them.
    try:
        ioc_alerts = correlate_flow_batch(batch)
    except Exception as exc:  # noqa: BLE001 - correlation must never break ingest
        print(f"IOC correlation failed for {batch.batch_id}: {exc}", file=sys.stderr)
        return
    for alert in ioc_alerts:
        state.alert_store.append(alert)

    # 2. Cross-source enrichment reads historical DetectionResults; a single
    #    corrupt/aged record (schema drift, dirty data) is skipped rather than
    #    aborting — and any failure here leaves the IOC alerts above intact.
    try:
        detections: list[DetectionResult] = []
        for record in state.vulnerability_store.tail(CROSS_SOURCE_WINDOW):
            try:
                detections.append(DetectionResult.model_validate(record))
            except Exception:  # noqa: BLE001 - skip one corrupt historical record
                continue
        cross_alerts = cross_source_alerts(
            batch.batch_id,
            batch.collected_at,
            ioc_alerts,
            detections,
        )
    except Exception as exc:  # noqa: BLE001 - cross-source is enrichment only
        print(f"cross-source correlation failed for {batch.batch_id}: {exc}", file=sys.stderr)
        return
    for alert in cross_alerts:
        state.alert_store.append(alert)


@router.post(
    "/capability-graph",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_capability_graph(graph: CapabilityGraph, request: Request) -> IngestAck:
    """Store a red-team capability graph (technique pre/postconditions + templates).

    This is reference knowledge for attack-path prediction; the newest one wins.
    fusion never executes anything from it — it only reasons over the declared facts.
    """
    request.app.state.capability_graph_store.append(graph)
    return IngestAck(id=f"{graph.source}:{graph.ontology_version}")
