"""Ingest endpoints for scanner and collector uploads."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, status
from pydantic import BaseModel
from starlette.datastructures import State

from ..correlate import correlate_trace_batch, cross_source_alerts, ip_host_index
from ..detect import combine_findings, detect_report, resolve_ecosystem, scanner_findings
from ..schemas import AssetReport, CapabilityGraph, DetectionResult, GuardEventBatch, TraceBatch

logger = logging.getLogger(__name__)

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
    """Store an uploaded asset report and run best-effort vulnerability detection.

    Idempotent on ``report_id``: a retried upload the analyzer already processed
    is acknowledged again with the same ``202`` but not re-stored or re-detected.
    """
    if request.app.state.ingest_seen.check_and_add(f"asset-report:{report.report_id}"):
        logger.info("duplicate asset-report %s ignored (idempotent retry)", report.report_id)
        return IngestAck(id=report.report_id)
    store_asset_report(report, request.app.state)
    return IngestAck(id=report.report_id)


def store_asset_report(report: AssetReport, state: State) -> None:
    """Persist an asset report and run best-effort detection.

    Shared by the HTTP ingest handler and the in-process scan-job runner
    (`analyzer.deploy.trigger`) so a admin-triggered scan lands identically to an
    agent upload.
    """
    state.asset_report_store.append(report)
    _auto_detect(report, state)


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
            logger.warning("detection failed for %s: %s", report.report_id, exc)

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
    "/trace-batch",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_trace_batch(batch: TraceBatch, request: Request) -> IngestAck:
    """Store an uploaded network trace batch and run best-effort alert correlation.

    Idempotent on ``batch_id``: a retried upload is acknowledged again but not
    re-stored or re-correlated.
    """
    if request.app.state.ingest_seen.check_and_add(f"trace-batch:{batch.batch_id}"):
        logger.info("duplicate trace-batch %s ignored (idempotent retry)", batch.batch_id)
        return IngestAck(id=batch.batch_id)
    store_trace_batch(batch, request.app.state)
    return IngestAck(id=batch.batch_id)


def store_trace_batch(batch: TraceBatch, state: State) -> None:
    """Persist a trace batch and run best-effort correlation.

    Shared by the HTTP ingest handler and the in-process scan-job runner.
    """
    state.trace_batch_store.append(batch)
    _correlate(batch, state)


def _correlate(batch: TraceBatch, state: State) -> None:
    """Best-effort: derive alerts from flow threat-intel hits, persist.

    Never lets a correlation error fail the ingest (the batch is already
    safely stored). The pure IOC alerts are persisted first and unconditionally;
    only the cross-source enrichment (which reads historical detections) is
    allowed to degrade on bad/aged data — it must not drop the IOC alerts.
    """
    # 0. Build an IP -> asset host_id index from recent AssetReports so IOC alerts
    #    (and the cross-source join below) reference the *scanned asset* a flow
    #    endpoint belongs to, not the collector vantage point (C3). Best-effort:
    #    a bad index just degrades to observer-id attribution, never bails ingest.
    ip_index: dict[str, str] = {}
    try:
        reports = []
        for record in state.asset_report_store.tail(CROSS_SOURCE_WINDOW):
            try:
                reports.append(AssetReport.model_validate(record))
            except Exception:  # noqa: BLE001 - skip one corrupt historical record
                continue
        ip_index = ip_host_index(reports)
    except Exception as exc:  # noqa: BLE001 - index is enrichment only
        logger.warning("IP->host index build failed for %s: %s", batch.batch_id, exc)

    # 1. IOC alerts are a pure function of the batch (+ the IP index) — compute and
    #    persist first so a later cross-source failure can never lose them.
    try:
        ioc_alerts = correlate_trace_batch(batch, ip_index)
    except Exception as exc:  # noqa: BLE001 - correlation must never break ingest
        logger.warning("IOC correlation failed for %s: %s", batch.batch_id, exc)
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
        logger.warning("cross-source correlation failed for %s: %s", batch.batch_id, exc)
        return
    for alert in cross_alerts:
        state.alert_store.append(alert)


@router.post(
    "/guard-event",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_guard_event(batch: GuardEventBatch, request: Request) -> IngestAck:
    """Store a real-time protection event batch from `agent-guard`.

    v1 is store-only: guard events are persisted for the admin / later analysis.
    Cross-source correlation (joining guard network/IDS events against host CVE
    detections to raise compound alerts) is deferred to a follow-up — the events
    carry enough provenance (`host_id`, `indicator`, timestamps) to add it later
    without a contract change.

    Idempotent on ``batch_id``: a retried upload is acknowledged again but not
    re-stored.
    """
    if request.app.state.ingest_seen.check_and_add(f"guard-event:{batch.batch_id}"):
        logger.info("duplicate guard-event %s ignored (idempotent retry)", batch.batch_id)
        return IngestAck(id=batch.batch_id)
    request.app.state.guard_event_store.append(batch)
    return IngestAck(id=batch.batch_id)


@router.post(
    "/capability-graph",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_capability_graph(graph: CapabilityGraph, request: Request) -> IngestAck:
    """Store a red-team capability graph (technique pre/postconditions + templates).

    This is reference knowledge for attack-path prediction; the newest one wins.
    analyzer never executes anything from it — it only reasons over the declared facts.
    """
    request.app.state.capability_graph_store.append(graph)
    return IngestAck(id=f"{graph.source}:{graph.ontology_version}")
