"""Internal ingest endpoints for telemetry forwarded by Form."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import APIRouter, Request, status
from pydantic import BaseModel
from starlette.datastructures import State

from ..correlate import (
    correlate_guard_batch,
    correlate_trace_batch,
    cross_source_alerts,
    guard_compound_alerts,
    ip_host_index,
)
from ..detect import combine_findings, detect_report, resolve_ecosystem, scanner_findings
from ..schemas import AssetReport, CapabilityGraph, DetectionResult, GuardEventBatch, TraceBatch

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])

# How many recent DetectionResults the cross-source correlation scans for
# high/critical vulnerable hosts. Bounded so correlation stays cheap; a host
# whose detection has aged out of this window won't get a cross-source alert.
CROSS_SOURCE_WINDOW = 500
MAX_DERIVED_RECORDS_PER_INGEST = 256
MAX_DERIVED_BYTES_PER_INGEST = 4 * 1024 * 1024
MAX_DERIVED_VULNERABILITIES = 4096


@dataclass
class _DerivedBudget:
    """Per-ingest persistence ceiling for attacker-influenced fan-out."""

    records: int = 0
    bytes: int = 0

    def append(self, store, record: BaseModel) -> bool:  # type: ignore[no-untyped-def]
        encoded_bytes = len(record.model_dump_json().encode("utf-8"))
        if (
            self.records >= MAX_DERIVED_RECORDS_PER_INGEST
            or self.bytes + encoded_bytes > MAX_DERIVED_BYTES_PER_INGEST
        ):
            logger.warning(
                "derived persistence truncated at %d record(s) / %d byte(s)",
                self.records,
                self.bytes,
            )
            return False
        store.append(record)
        self.records += 1
        self.bytes += encoded_bytes
        return True


class IngestAck(BaseModel):
    """Returned to Form after a successful ingest.

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

    Idempotent on ``report_id``: a retried forward Analyzer already processed
    is acknowledged again with the same ``202`` but not re-stored or re-detected.
    """
    # Authenticated Agent namespaces cannot reserve another endpoint's envelope
    # id.  Historical/Form-pulled reports intentionally share the legacy
    # namespace because they have no source_agent_id.
    source = report.source_agent_id or "legacy"
    key = f"asset-report:{source}:{report.report_id}"
    if request.app.state.ingest_seen.check_and_add(key):
        logger.info("duplicate asset-report %s ignored (idempotent retry)", report.report_id)
        return IngestAck(id=report.report_id)
    try:
        store_asset_report(report, request.app.state)
    except Exception:
        # Release the reservation so Form's retry is processed
        # instead of being silently deduped after a failed durable store.
        request.app.state.ingest_seen.discard(key)
        raise
    return IngestAck(id=report.report_id)


def store_asset_report(report: AssetReport, state: State) -> None:
    """Persist an asset report and run best-effort detection.

    Form sends both Agent uploads and Form-triggered scan artifacts through this
    HTTP path, so every report follows the same persistence/detection flow.
    """
    state.asset_report_store.append(report)
    try:
        _auto_detect(report, state)
    except Exception:  # noqa: BLE001 - main report is durable; derived work is best-effort
        logger.exception(
            "derived vulnerability persistence failed after storing asset report %s",
            report.report_id,
        )


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

    vulnerabilities = combine_findings(osv_vulns, malware)[:MAX_DERIVED_VULNERABILITIES]
    if not vulnerabilities:
        return

    _DerivedBudget().append(
        state.vulnerability_store,
        DetectionResult(
            report_id=report.report_id,
            host_id=report.host.host_id,
            collected_at=report.collected_at,
            ecosystem=ecosystem,
            vulnerabilities=vulnerabilities,
        ),
    )


@router.post(
    "/trace-batch",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_trace_batch(batch: TraceBatch, request: Request) -> IngestAck:
    """Store an uploaded network trace batch and run best-effort alert correlation.

    Idempotent on ``batch_id``: a retried forward is acknowledged again but not
    re-stored or re-correlated.
    """
    source = batch.source_agent_id or "legacy"
    key = f"trace-batch:{source}:{batch.batch_id}"
    if request.app.state.ingest_seen.check_and_add(key):
        logger.info("duplicate trace-batch %s ignored (idempotent retry)", batch.batch_id)
        return IngestAck(id=batch.batch_id)
    try:
        store_trace_batch(batch, request.app.state)
    except Exception:
        request.app.state.ingest_seen.discard(key)
        raise
    return IngestAck(id=batch.batch_id)


def store_trace_batch(batch: TraceBatch, state: State) -> None:
    """Persist a trace batch and run best-effort correlation.

    Shared by every Form-originated trace ingest.
    """
    state.trace_batch_store.append(batch)
    try:
        _correlate(batch, state)
    except Exception:  # noqa: BLE001 - main batch is durable; derived work is best-effort
        logger.exception(
            "derived alert persistence failed after storing trace batch %s", batch.batch_id
        )


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
    budget = _DerivedBudget()
    persisted_ioc = []
    for alert in ioc_alerts:
        if not budget.append(state.alert_store, alert):
            break
        persisted_ioc.append(alert)

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
            persisted_ioc,
            detections,
        )
    except Exception as exc:  # noqa: BLE001 - cross-source is enrichment only
        logger.warning("cross-source correlation failed for %s: %s", batch.batch_id, exc)
        return
    for alert in cross_alerts:
        if not budget.append(state.alert_store, alert):
            break


@router.post(
    "/guard-event",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_guard_event(batch: GuardEventBatch, request: Request) -> IngestAck:
    """Store a real-time protection event batch from `agent-respond` and correlate it.

    High-signal guard events (network IOC hits, on-access malware, high-severity
    IDS) become Alerts, and a compound alert is raised when a detection lands on a
    host with high/critical CVE posture. Guard network IOC hits share the trace
    IOC ``alert_key``, so a C2 seen by both folds into one alert.

    Idempotent on ``batch_id``: a retried upload is acknowledged again but not
    re-stored or re-correlated.
    """
    source = batch.source_agent_id or "legacy"
    key = f"guard-event:{source}:{batch.batch_id}"
    if request.app.state.ingest_seen.check_and_add(key):
        logger.info("duplicate guard-event %s ignored (idempotent retry)", batch.batch_id)
        return IngestAck(id=batch.batch_id)
    try:
        store_guard_batch(batch, request.app.state)
    except Exception:
        request.app.state.ingest_seen.discard(key)
        raise
    return IngestAck(id=batch.batch_id)


def store_guard_batch(batch: GuardEventBatch, state: State) -> None:
    """Persist a guard event batch and run best-effort correlation."""
    state.guard_event_store.append(batch)
    try:
        _correlate_guard(batch, state)
    except Exception:  # noqa: BLE001 - main batch is durable; derived work is best-effort
        logger.exception(
            "derived alert persistence failed after storing guard batch %s", batch.batch_id
        )


def _correlate_guard(batch: GuardEventBatch, state: State) -> None:
    """Best-effort: derive alerts from guard detections, persist.

    Never lets a correlation error fail the ingest (the batch is already stored).
    Base guard alerts are persisted first and unconditionally; only the
    cross-source enrichment (which reads historical detections) may degrade.
    """
    try:
        guard_alerts = correlate_guard_batch(batch)
    except Exception as exc:  # noqa: BLE001 - correlation must never break ingest
        logger.warning("guard correlation failed for %s: %s", batch.batch_id, exc)
        return
    budget = _DerivedBudget()
    persisted_guard = []
    for alert in guard_alerts:
        if not budget.append(state.alert_store, alert):
            break
        persisted_guard.append(alert)

    # Compound alerts: a guard detection on a host with high/critical CVE posture.
    try:
        detections: list[DetectionResult] = []
        for record in state.vulnerability_store.tail(CROSS_SOURCE_WINDOW):
            try:
                detections.append(DetectionResult.model_validate(record))
            except Exception:  # noqa: BLE001 - skip one corrupt historical record
                continue
        compound = guard_compound_alerts(
            batch.batch_id, batch.collected_at, persisted_guard, detections
        )
    except Exception as exc:  # noqa: BLE001 - cross-source is enrichment only
        logger.warning("guard cross-source correlation failed for %s: %s", batch.batch_id, exc)
        return
    for alert in compound:
        if not budget.append(state.alert_store, alert):
            break


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
