"""Internal ingest endpoints for telemetry forwarded by Form."""

from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, BeforeValidator, Field
from starlette.datastructures import State

from ..correlate import (
    correlate_guard_batch,
    correlate_trace_batch,
    cross_source_alerts,
    guard_compound_alerts,
    ip_host_index,
)
from ..correlate.limits import CorrelationLimitState
from ..detect import (
    DebianTrackerStore,
    combine_findings,
    coverage_matrix,
    detect_kali_packages,
    detect_report,
    kali_tracker_coverage,
    merge_kali_tracker_status,
    package_coverage,
    resolve_ecosystem,
    scanner_findings,
)
from ..detect.limits import FindingLimitState
from ..schemas import (
    Alert,
    AlertStatus,
    AssetReport,
    CapabilityGraph,
    CoverageStatus,
    DetectionCoverage,
    DetectionResult,
    DetectionStatus,
    DetectorKind,
    DetectorRun,
    DetectorRunStatus,
    GuardEventBatch,
    HostInfo,
    MdeAlert,
    MdeIncident,
    MdeSecurityBatch,
    MdvmDeviceSnapshot,
    MdvmSoftwareVulnerability,
    MdvmVulnerabilityBatch,
    Package,
    Severity,
    TraceBatch,
    Vulnerability,
)
from .ingest_queue import LedgerConflictError, LedgerTask, TaskKind

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])


def _forbid_unknown(model):  # type: ignore[no-untyped-def]
    """Build an inbound-only recursive extra-field validator.

    Stored historical records still use ``StrictModel.extra='ignore'`` so a
    rolling upgrade can read old/new schema variants. The trust boundary is
    stricter: unknown wire data is rejected with 422 instead of being accepted
    and silently discarded.
    """

    def validate(value: Any):  # type: ignore[no-untyped-def]
        return model.model_validate(value, extra="forbid")

    return validate


InboundAssetReport = Annotated[AssetReport, BeforeValidator(_forbid_unknown(AssetReport))]
InboundTraceBatch = Annotated[TraceBatch, BeforeValidator(_forbid_unknown(TraceBatch))]
InboundGuardEventBatch = Annotated[
    GuardEventBatch,
    BeforeValidator(_forbid_unknown(GuardEventBatch)),
]
InboundMdeSecurityBatch = Annotated[
    MdeSecurityBatch,
    BeforeValidator(_forbid_unknown(MdeSecurityBatch)),
]
InboundMdvmVulnerabilityBatch = Annotated[
    MdvmVulnerabilityBatch,
    BeforeValidator(_forbid_unknown(MdvmVulnerabilityBatch)),
]

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
    truncated: bool = False
    truncation_reason: str | None = None

    def append(self, store, record: BaseModel) -> bool:  # type: ignore[no-untyped-def]
        # Alert ids are deterministic for one source envelope. A retry after a
        # later derived write failed must not append already-committed alerts a
        # second time (which would inflate occurrence counts in the UI).
        alert_id = getattr(record, "alert_id", None)
        if isinstance(alert_id, str) and store.find_one("alert_id", alert_id) is not None:
            return True
        encoded_bytes = len(record.model_dump_json().encode("utf-8"))
        if (
            self.records >= MAX_DERIVED_RECORDS_PER_INGEST
            or self.bytes + encoded_bytes > MAX_DERIVED_BYTES_PER_INGEST
        ):
            self.truncated = True
            self.truncation_reason = (
                "max_records" if self.records >= MAX_DERIVED_RECORDS_PER_INGEST else "max_bytes"
            )
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


DerivedRunStatus = Literal["complete", "partial", "failed"]
DerivedAckStatus = Literal["pending", "complete", "partial", "failed"]


@dataclass
class _DerivedOutcome:
    status: DerivedRunStatus = "complete"
    records: int = 0
    truncated: bool = False
    reason: str | None = None


def _failed_outcome(kind: str, envelope_id: str, exc: Exception) -> _DerivedOutcome:
    """Log and meter a durable-raw/failed-derived split explicitly."""
    logger.exception("derived %s persistence failed after storing %s", kind, envelope_id)
    return _DerivedOutcome(status="failed", reason=type(exc).__name__)


def _observe_outcome(outcome: _DerivedOutcome) -> None:
    from .. import metrics as metrics_mod

    if outcome.status == "failed":
        metrics_mod.inc("kcatta_derived_failures_total")
    elif outcome.status == "partial":
        metrics_mod.inc("kcatta_derived_partial_total")
    if outcome.truncated:
        metrics_mod.inc("kcatta_derived_truncations_total")


def _budget_outcome(budget: _DerivedBudget, reasons: list[str]) -> _DerivedOutcome:
    reason = reasons[0] if reasons else budget.truncation_reason
    return _DerivedOutcome(
        status="partial" if reason or budget.truncated else "complete",
        records=budget.records,
        truncated=budget.truncated,
        reason=reason,
    )


class IngestAck(BaseModel):
    """Returned after durable acceptance or synchronous derived completion.

    `accepted` is redundant given the 202 status code but lets clients
    avoid status-code parsing in shell pipelines. ``queued`` plus
    ``derived_status=pending`` means the full raw envelope is durable in the
    outbox while detection/correlation continues in the background.
    """

    accepted: bool = True
    id: str
    duplicate: bool = False
    queued: bool = False
    derived_status: DerivedAckStatus | None = None
    derived_records: int = Field(default=0, ge=0)
    derived_truncated: bool = False
    derived_reason: str | None = None


class IngestDerivedStatus(BaseModel):
    """Durable aggregate state for one logical ingest envelope and its chunks."""

    kind: TaskKind
    id: str
    source: str
    state: Literal["pending", "processing", "complete", "partial"]
    children: int = Field(ge=1)
    attempts: int = Field(ge=0)
    derived_records: int = Field(ge=0)
    derived_truncated: bool = False
    derived_reason: str | None = None
    last_error: str | None = None
    next_attempt_at: float | None = None
    updated_at: float


def _aggregate_task_state(tasks: list[LedgerTask]) -> IngestDerivedStatus:
    rank = {"complete": 0, "partial": 1, "pending": 2, "processing": 3}
    state = max((task.state for task in tasks), key=rank.__getitem__)
    reasons = tuple(dict.fromkeys(task.derived_reason for task in tasks if task.derived_reason))
    errors = tuple(dict.fromkeys(task.last_error for task in tasks if task.last_error))
    due = [task.next_attempt_at for task in tasks if task.state == "pending"]
    first = tasks[0]
    return IngestDerivedStatus(
        kind=first.kind,
        id=first.envelope_id,
        source=first.key[len(first.kind) + 1 : -(len(first.envelope_id) + 1)],
        state=state,
        children=len(tasks),
        attempts=sum(task.attempts for task in tasks),
        derived_records=sum(task.derived_records for task in tasks),
        derived_truncated=any(task.derived_truncated for task in tasks),
        derived_reason=(", ".join(reasons)[:2048] or None),
        last_error=(", ".join(errors)[:2048] or None),
        next_attempt_at=min(due) if due else None,
        updated_at=max(task.updated_at for task in tasks),
    )


@router.get("/status", response_model=IngestDerivedStatus)
async def get_ingest_status(
    request: Request,
    kind: TaskKind,
    envelope_id: Annotated[str, Query(alias="id", min_length=1, max_length=256)],
    source: Annotated[str, Query(min_length=1, max_length=256)] = "legacy",
) -> IngestDerivedStatus:
    """Fetch the current derived state, aggregating every retained child chunk."""

    tasks = request.app.state.ingest_ledger.lineage(
        kind=kind,
        source=source,
        envelope_id=envelope_id,
    )
    if not tasks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="ingest envelope status is not retained",
        )
    aggregated = _aggregate_task_state(tasks)
    # The first child carries the logical root id by construction. Explicitly
    # echo the query value so callers never need to understand chunk suffixes.
    return aggregated.model_copy(update={"id": envelope_id, "source": source})


def _ack(
    envelope_id: str,
    outcome: _DerivedOutcome,
    *,
    duplicate: bool = False,
) -> IngestAck:
    if not duplicate:
        _observe_outcome(outcome)
    if outcome.status == "failed":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "message": "raw telemetry stored but derived processing failed; retry safely",
                "id": envelope_id,
                "derived_status": outcome.status,
                "derived_reason": outcome.reason,
            },
            headers={"Retry-After": "5"},
        )
    return IngestAck(
        id=envelope_id,
        duplicate=duplicate,
        derived_status=outcome.status,
        derived_records=outcome.records,
        derived_truncated=outcome.truncated,
        derived_reason=outcome.reason,
    )


def _pending_ack(envelope_id: str, *, duplicate: bool) -> IngestAck:
    return IngestAck(
        id=envelope_id,
        duplicate=duplicate,
        queued=True,
        derived_status="pending",
    )


def _task_outcome(task: LedgerTask) -> _DerivedOutcome | None:
    if not task.final:
        return None
    return _DerivedOutcome(
        status=task.state,
        records=task.derived_records,
        truncated=task.derived_truncated,
        reason=task.derived_reason,
    )


def _raw_already_stored(store, id_field: str, envelope_id: str, source: str) -> bool:  # type: ignore[no-untyped-def]
    """Recognize a retry whose raw envelope was committed before derivation failed."""
    find_one = getattr(store, "find_one", None)
    if find_one is None:
        return False
    record = find_one(id_field, envelope_id)
    return bool(record and (record.get("source_agent_id") or "legacy") == source)


def _process_ingest_task(task: LedgerTask, state: State) -> _DerivedOutcome:
    """Copy one durable queued envelope into its raw store, then derive results."""
    if task.kind == "asset-report":
        report = AssetReport.model_validate_json(task.payload)
        source = report.source_agent_id or "legacy"
        raw_exists = _raw_already_stored(
            state.asset_report_store,
            "report_id",
            report.report_id,
            source,
        )
        return store_asset_report(report, state, persist_raw=not raw_exists)
    if task.kind == "trace-batch":
        batch = TraceBatch.model_validate_json(task.payload)
        source = batch.source_agent_id or "legacy"
        raw_exists = _raw_already_stored(
            state.trace_batch_store,
            "batch_id",
            batch.batch_id,
            source,
        )
        return store_trace_batch(batch, state, persist_raw=not raw_exists)
    batch = GuardEventBatch.model_validate_json(task.payload)
    source = batch.source_agent_id or "legacy"
    raw_exists = _raw_already_stored(
        state.guard_event_store,
        "batch_id",
        batch.batch_id,
        source,
    )
    return store_guard_batch(batch, state, persist_raw=not raw_exists)


def process_queued_ingest(task: LedgerTask, state: State) -> _DerivedOutcome:
    """Public worker adapter kept beside the ingest derivation implementation."""
    return _process_ingest_task(task, state)


def _observe_ingest(kind: TaskKind) -> None:
    from .. import metrics as metrics_mod

    metric = {
        "asset-report": "kcatta_ingest_asset_reports_total",
        "trace-batch": "kcatta_ingest_trace_batches_total",
        "guard-event": "kcatta_ingest_guard_events_total",
    }[kind]
    metrics_mod.inc(metric)


def _run_inline(request: Request, task: LedgerTask) -> IngestAck:
    """Process a claimed task synchronously while heartbeating its durable lease."""
    assert task.lease_token is not None
    ledger = request.app.state.ingest_ledger
    lease_seconds = request.app.state.derived_worker.lease_seconds
    stop = threading.Event()

    def heartbeat() -> None:
        while not stop.wait(max(0.05, lease_seconds / 3)):
            if not ledger.extend_lease(
                task.key,
                task.lease_token,
                lease_seconds=lease_seconds,
            ):
                return

    lease_thread = threading.Thread(target=heartbeat, name="analyzer-inline-lease", daemon=True)
    lease_thread.start()
    try:
        outcome = _process_ingest_task(task, request.app.state)
    except Exception as exc:
        ledger.retry(
            task.key,
            task.lease_token,
            reason=type(exc).__name__,
            delay_seconds=0,
        )
        raise
    finally:
        stop.set()
        lease_thread.join(timeout=1.0)

    if outcome.status == "failed":
        ledger.retry(
            task.key,
            task.lease_token,
            reason=outcome.reason or "derived_processing_failed",
            delay_seconds=0,
        )
    else:
        committed = ledger.complete(
            task.key,
            task.lease_token,
            status=outcome.status,
            records=outcome.records,
            truncated=outcome.truncated,
            reason=outcome.reason,
        )
        if not committed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="derived task lease was lost; retry safely",
                headers={"Retry-After": "1"},
            )
    return _ack(task.envelope_id, outcome)


def _ingest_envelope(
    request: Request,
    *,
    key: str,
    kind: TaskKind,
    envelope_id: str,
    payload: BaseModel,
) -> IngestAck:
    try:
        submitted = request.app.state.ingest_ledger.submit(
            key=key,
            kind=kind,
            envelope_id=envelope_id,
            payload=payload.model_dump_json(),
        )
    except LedgerConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="envelope id was reused with different content",
        ) from exc

    if submitted.created:
        _observe_ingest(kind)
    if outcome := _task_outcome(submitted.task):
        return _ack(envelope_id, outcome, duplicate=True)

    if request.app.state.derived_async:
        request.app.state.derived_worker.notify()
        return _pending_ack(envelope_id, duplicate=not submitted.created)

    claimed = request.app.state.ingest_ledger.claim(
        key,
        lease_seconds=request.app.state.derived_worker.lease_seconds,
    )
    if claimed is None:
        # Another process may have completed between submit() and claim().
        current = request.app.state.ingest_ledger.get(key)
        if current is not None and (outcome := _task_outcome(current)):
            return _ack(envelope_id, outcome, duplicate=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ingest for this envelope is still processing; retry safely",
            headers={"Retry-After": "1"},
        )
    return _run_inline(request, claimed)


@router.post(
    "/asset-report",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_asset_report(report: InboundAssetReport, request: Request) -> IngestAck:
    """Durably accept an asset report and derive vulnerability results once."""
    source = report.source_agent_id or "legacy"
    key = f"asset-report:{source}:{report.report_id}"
    return _ingest_envelope(
        request,
        key=key,
        kind="asset-report",
        envelope_id=report.report_id,
        payload=report,
    )


def store_asset_report(
    report: AssetReport,
    state: State,
    *,
    persist_raw: bool = True,
) -> _DerivedOutcome:
    """Persist an asset report and run best-effort detection.

    Form sends both Agent uploads and Form-triggered scan artifacts through this
    HTTP path, so every report follows the same persistence/detection flow.
    """
    if persist_raw:
        state.asset_report_store.append(report)
    else:
        # Crash recovery: if the derived row committed before the ledger outcome
        # did, replay that deterministic result instead of appending it again.
        existing = state.vulnerability_store.find_one("report_id", report.report_id)
        if existing is not None:
            result = DetectionResult.model_validate(existing)
            if result.detection_status != DetectionStatus.FAILED:
                complete = (
                    result.detection_status == DetectionStatus.COMPLETE and not result.truncated
                )
                return _DerivedOutcome(
                    status="complete" if complete else "partial",
                    records=1,
                    truncated=result.truncated,
                    reason=result.status_reason or result.truncation_reason,
                )
    try:
        return _auto_detect(report, state)
    except Exception as exc:  # noqa: BLE001 - raw report is already durable
        return _failed_outcome("vulnerability", f"asset report {report.report_id}", exc)


def _auto_detect(report: AssetReport, state: State) -> _DerivedOutcome:
    """Run detection and persist a status row even when findings are empty.

    The status differentiates a verified clean pass from disabled, partial, or
    failed OSV coverage. Scanner-native findings are preserved when OSV fails.
    """
    scanner_limit = FindingLimitState()
    malware = scanner_findings(report, limit_state=scanner_limit)
    osv_vulns: list = []
    ecosystem = resolve_ecosystem(report, state.osv_ecosystem) or ""
    tracker_limit = FindingLimitState()
    # Direct/unit callers predating the Tracker store still get conservative
    # empty coverage instead of failing before the existing OSV error path.
    tracker_store = getattr(state, "debian_tracker_store", None) or DebianTrackerStore()
    tracker = detect_kali_packages(
        report,
        tracker_store,
        limit_state=tracker_limit,
    )
    coverage = package_coverage(
        tracker.osv_report,
        ecosystem or None,
        getattr(state, "osv_synced_ecosystems", None),
    )
    detection_status = DetectionStatus.COMPLETE
    status_reason: str | None = None
    scanned_package_count = 0
    osv_limit = FindingLimitState()

    store = state.osv_store
    if store.record_count <= 0:
        detection_status = DetectionStatus.DISABLED
        status_reason = "osv_store_empty"
    else:
        if coverage.total == 0 and tracker.candidate_count == 0:
            detection_status = DetectionStatus.PARTIAL
            status_reason = "no_package_inventory"
        elif getattr(state, "osv_synced_ecosystems", None) is None:
            detection_status = DetectionStatus.PARTIAL
            status_reason = "osv_sync_incomplete"
        if coverage.total and coverage.resolved == 0:
            detection_status = DetectionStatus.PARTIAL
            status_reason = "ecosystem_unresolved"
        elif coverage.unsupported == coverage.resolved and coverage.unsupported > 0:
            detection_status = DetectionStatus.PARTIAL
            status_reason = "osv_ecosystem_unsupported"
        elif coverage.uncovered == coverage.resolved and coverage.uncovered > 0:
            detection_status = DetectionStatus.PARTIAL
            status_reason = (
                "some_osv_ecosystems_unsupported"
                if coverage.unsupported
                else "osv_ecosystem_not_synced"
            )
        else:
            try:
                # Packages with their own ecosystem remain detectable even when the
                # host OS cannot provide a default ecosystem.
                osv_vulns = detect_report(
                    coverage.detection_report,
                    store,
                    ecosystem or None,
                    limit_state=osv_limit,
                )
            except Exception as exc:  # noqa: BLE001 - detection must never break ingest
                logger.warning("detection failed for %s: %s", report.report_id, exc)
                detection_status = DetectionStatus.FAILED
                status_reason = "osv_detection_failed"
            else:
                scanned_package_count = coverage.covered
                if coverage.unsupported:
                    detection_status = DetectionStatus.PARTIAL
                    status_reason = "some_osv_ecosystems_unsupported"
                elif coverage.uncovered:
                    detection_status = DetectionStatus.PARTIAL
                    status_reason = "some_osv_ecosystems_not_synced"
                elif coverage.unresolved:
                    detection_status = DetectionStatus.PARTIAL
                    status_reason = "some_package_ecosystems_unresolved"

    scanned_package_count += tracker.verified_count
    detection_status, status_reason = merge_kali_tracker_status(
        detection_status,
        status_reason,
        tracker,
        tracker_store,
        tracker_limit,
        osv_candidate_count=coverage.total,
    )

    combine_limit = FindingLimitState()
    vulnerabilities = combine_findings(
        [*osv_vulns, *tracker.findings],
        malware,
        max_findings=MAX_DERIVED_VULNERABILITIES,
        limit_state=combine_limit,
    )
    limit_states = (osv_limit, tracker_limit, scanner_limit, combine_limit)
    incomplete_reason = next(
        (limit.incomplete_reason for limit in limit_states if limit.incomplete_reason),
        None,
    )
    if incomplete_reason and detection_status not in {
        DetectionStatus.DISABLED,
        DetectionStatus.FAILED,
    }:
        detection_status = DetectionStatus.PARTIAL
        status_reason = incomplete_reason
    truncated = any(limit.truncated for limit in limit_states)
    truncation_reason = next((limit.reason for limit in limit_states if limit.reason), None)
    matrix = coverage_matrix(
        report,
        coverage,
        osv_vulns,
        malware,
        default_ecosystem=ecosystem or None,
        osv_store_available=store.record_count > 0,
        osv_sync_known=getattr(state, "osv_synced_ecosystems", None) is not None,
        detection_status=detection_status,
        status_reason=status_reason,
        osv_incomplete_reason=osv_limit.incomplete_reason or osv_limit.reason,
        scanner_incomplete_reason=scanner_limit.incomplete_reason or scanner_limit.reason,
        debian_tracker_coverage=kali_tracker_coverage(
            tracker,
            tracker_store,
            tracker_limit,
        ),
    )

    budget = _DerivedBudget()
    persisted = budget.append(
        state.vulnerability_store,
        DetectionResult(
            report_id=report.report_id,
            host_id=report.host.host_id,
            collected_at=report.collected_at,
            ecosystem=ecosystem,
            vulnerabilities=vulnerabilities,
            detection_status=detection_status,
            status_reason=status_reason,
            scanned_package_count=scanned_package_count,
            unresolved_package_count=coverage.unresolved + tracker.unverified_count,
            uncovered_package_count=coverage.uncovered,
            truncated=truncated,
            truncation_reason=truncation_reason,
            coverage=matrix,
        ),
    )
    if not persisted:
        raise RuntimeError(f"DetectionResult exceeded derived {budget.truncation_reason} budget")
    status: DerivedAckStatus
    if detection_status == DetectionStatus.FAILED:
        status = "failed"
    elif (
        detection_status == DetectionStatus.COMPLETE
        and not truncated
        and all(row.status.value in {"complete", "disabled"} for row in matrix)
    ):
        status = "complete"
    else:
        status = "partial"
    matrix_reason = next(
        (
            row.reason
            for row in matrix
            if row.status.value not in {"complete", "disabled"} and row.reason
        ),
        None,
    )
    reason = status_reason or truncation_reason or matrix_reason
    return _DerivedOutcome(
        status=status,
        records=1,
        truncated=truncated,
        reason=reason,
    )


@router.post(
    "/trace-batch",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_trace_batch(batch: InboundTraceBatch, request: Request) -> IngestAck:
    """Durably accept a trace batch and derive correlated alerts once."""
    source = batch.source_agent_id or "legacy"
    key = f"trace-batch:{source}:{batch.batch_id}"
    return _ingest_envelope(
        request,
        key=key,
        kind="trace-batch",
        envelope_id=batch.batch_id,
        payload=batch,
    )


def store_trace_batch(
    batch: TraceBatch,
    state: State,
    *,
    persist_raw: bool = True,
) -> _DerivedOutcome:
    """Persist a trace batch and run best-effort correlation.

    Shared by every Form-originated trace ingest.
    """
    if persist_raw:
        state.trace_batch_store.append(batch)
    try:
        return _correlate(batch, state)
    except Exception as exc:  # noqa: BLE001 - raw batch is already durable
        return _failed_outcome("alert", f"trace batch {batch.batch_id}", exc)


def _correlate(batch: TraceBatch, state: State) -> _DerivedOutcome:
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
    partial_reasons: list[str] = []
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
        partial_reasons.append("ip_host_index_failed")

    # 1. IOC alerts are a pure function of the batch (+ the IP index) — compute and
    #    persist first so a later cross-source failure can never lose them.
    correlation_limit = CorrelationLimitState()
    try:
        ioc_alerts = correlate_trace_batch(batch, ip_index, correlation_limit)
    except Exception as exc:  # noqa: BLE001 - correlation must never break ingest
        logger.warning("IOC correlation failed for %s: %s", batch.batch_id, exc)
        return _DerivedOutcome(status="failed", reason="ioc_correlation_failed")
    budget = _DerivedBudget()
    if correlation_limit.truncated:
        budget.truncated = True
        budget.truncation_reason = correlation_limit.reason
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
            correlation_limit,
        )
    except Exception as exc:  # noqa: BLE001 - cross-source is enrichment only
        logger.warning("cross-source correlation failed for %s: %s", batch.batch_id, exc)
        partial_reasons.append("cross_source_correlation_failed")
        return _budget_outcome(budget, partial_reasons)
    if correlation_limit.truncated:
        budget.truncated = True
        budget.truncation_reason = budget.truncation_reason or correlation_limit.reason
    for alert in cross_alerts:
        if not budget.append(state.alert_store, alert):
            break
    return _budget_outcome(budget, partial_reasons)


@router.post(
    "/guard-event",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_guard_event(batch: InboundGuardEventBatch, request: Request) -> IngestAck:
    """Store a real-time protection event batch from `agent-respond` and correlate it.

    High-signal guard events (network IOC hits, on-access malware, high-severity
    IDS) become Alerts, and a compound alert is raised when a detection lands on a
    host with high/critical CVE posture. Guard network IOC hits share the trace
    IOC ``alert_key``, so a C2 seen by both folds into one alert.

    The envelope is first committed to the durable ledger. Async deployments
    acknowledge it as pending and let the leased worker retry correlation.
    """
    source = batch.source_agent_id or "legacy"
    key = f"guard-event:{source}:{batch.batch_id}"
    return _ingest_envelope(
        request,
        key=key,
        kind="guard-event",
        envelope_id=batch.batch_id,
        payload=batch,
    )


def store_guard_batch(
    batch: GuardEventBatch,
    state: State,
    *,
    persist_raw: bool = True,
) -> _DerivedOutcome:
    """Persist a guard event batch and run best-effort correlation."""
    if persist_raw:
        state.guard_event_store.append(batch)
    try:
        return _correlate_guard(batch, state)
    except Exception as exc:  # noqa: BLE001 - raw batch is already durable
        return _failed_outcome("alert", f"guard batch {batch.batch_id}", exc)


def _correlate_guard(batch: GuardEventBatch, state: State) -> _DerivedOutcome:
    """Best-effort: derive alerts from guard detections, persist.

    Never lets a correlation error fail the ingest (the batch is already stored).
    Base guard alerts are persisted first and unconditionally; only the
    cross-source enrichment (which reads historical detections) may degrade.
    """
    correlation_limit = CorrelationLimitState()
    try:
        guard_alerts = correlate_guard_batch(batch, correlation_limit)
    except Exception as exc:  # noqa: BLE001 - correlation must never break ingest
        logger.warning("guard correlation failed for %s: %s", batch.batch_id, exc)
        return _DerivedOutcome(status="failed", reason="guard_correlation_failed")
    budget = _DerivedBudget()
    if correlation_limit.truncated:
        budget.truncated = True
        budget.truncation_reason = correlation_limit.reason
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
            batch.batch_id,
            batch.collected_at,
            persisted_guard,
            detections,
            correlation_limit,
        )
    except Exception as exc:  # noqa: BLE001 - cross-source is enrichment only
        logger.warning("guard cross-source correlation failed for %s: %s", batch.batch_id, exc)
        return _DerivedOutcome(
            status="partial",
            records=budget.records,
            truncated=budget.truncated,
            reason="guard_cross_source_correlation_failed",
        )
    if correlation_limit.truncated:
        budget.truncated = True
        budget.truncation_reason = budget.truncation_reason or correlation_limit.reason
    for alert in compound:
        if not budget.append(state.alert_store, alert):
            break
    return _budget_outcome(budget, [])


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


_MDE_SCORE = {
    Severity.INFO: 15.0,
    Severity.LOW: 40.0,
    Severity.MEDIUM: 65.0,
    Severity.HIGH: 85.0,
    Severity.CRITICAL: 95.0,
}


def _mde_identifier(kind: str, tenant_id: str, external_id: str, version: str = "") -> str:
    digest = hashlib.sha256(
        f"{kind}\0{tenant_id}\0{external_id}\0{version}".encode()
    ).hexdigest()
    return f"mde-{kind}-{digest}"


def _mde_status(provider_status: str) -> AlertStatus:
    if provider_status.strip().lower() in {"resolved", "redirected"}:
        return AlertStatus.CLOSED
    return AlertStatus.OPEN


def _bounded_description(parts: list[str]) -> str:
    return "\n".join(part for part in parts if part)[:4096]


def _alert_from_mde_alert(tenant_id: str, item: MdeAlert) -> Alert:
    details = [item.description]
    details.append(f"Microsoft Defender alert: {item.alert_id}")
    details.append(f"Provider status: {item.provider_status}")
    if item.classification:
        details.append(f"Classification: {item.classification}")
    if item.determination:
        details.append(f"Determination: {item.determination}")
    if item.product_name or item.service_source:
        details.append(f"Source: {item.product_name or item.service_source}")
    if item.mitre_techniques:
        details.append(f"MITRE ATT&CK: {', '.join(item.mitre_techniques)}")
    if item.portal_url:
        details.append(f"Microsoft portal: {item.portal_url}")
    return Alert(
        alert_id=_mde_identifier(
            "alert-occurrence",
            tenant_id,
            item.alert_id,
            item.last_updated_at.isoformat(),
        ),
        alert_key=_mde_identifier("alert", tenant_id, item.alert_id),
        severity=item.severity,
        status=_mde_status(item.provider_status),
        score=_MDE_SCORE[item.severity],
        title=f"[MDE] {item.title}"[:4096],
        description=_bounded_description(details),
        related_asset_ids=item.related_asset_ids,
        evidence_truncated=item.evidence_truncated,
        created_at=item.created_at,
        updated_at=item.last_updated_at,
        last_seen=item.last_activity_at or item.last_updated_at,
    )


def _alert_from_mde_incident(tenant_id: str, item: MdeIncident) -> Alert:
    details = [item.description]
    details.append(f"Microsoft Defender incident: {item.incident_id}")
    details.append(f"Provider status: {item.provider_status}")
    if item.classification:
        details.append(f"Classification: {item.classification}")
    if item.determination:
        details.append(f"Determination: {item.determination}")
    if item.alert_ids:
        details.append(f"Related provider alerts: {', '.join(item.alert_ids)}")
    if item.portal_url:
        details.append(f"Microsoft portal: {item.portal_url}")
    return Alert(
        alert_id=_mde_identifier(
            "incident-occurrence",
            tenant_id,
            item.incident_id,
            item.last_updated_at.isoformat(),
        ),
        alert_key=_mde_identifier("incident", tenant_id, item.incident_id),
        severity=item.severity,
        status=_mde_status(item.provider_status),
        score=_MDE_SCORE[item.severity],
        title=f"[MDE Incident] {item.display_name}"[:4096],
        description=_bounded_description(details),
        related_asset_ids=item.related_asset_ids,
        evidence_truncated=item.relationships_truncated,
        created_at=item.created_at,
        updated_at=item.last_updated_at,
        last_seen=item.last_updated_at,
    )


def store_mde_security_batch(
    batch: MdeSecurityBatch,
    state: State,
    *,
    persist_raw: bool = True,
) -> _DerivedOutcome:
    """Persist one normalized MDE sync chunk and expose alerts in the common UI."""
    if persist_raw:
        state.mde_security_store.append(batch)
    budget = _DerivedBudget()
    for item in batch.alerts:
        if not budget.append(state.alert_store, _alert_from_mde_alert(batch.tenant_id, item)):
            break
    if not budget.truncated:
        for item in batch.incidents:
            if not budget.append(
                state.alert_store,
                _alert_from_mde_incident(batch.tenant_id, item),
            ):
                break
    return _budget_outcome(budget, [])


@router.post(
    "/mde-security-batch",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_mde_security_batch(
    batch: InboundMdeSecurityBatch,
    request: Request,
) -> IngestAck:
    """Idempotently accept one Form-owned read-only MDE synchronization chunk."""
    store = request.app.state.mde_security_store
    existing = store.find_one("batch_id", batch.batch_id)
    if existing is not None:
        stored = MdeSecurityBatch.model_validate(existing)
        if stored.model_dump(mode="json") != batch.model_dump(mode="json"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="MDE batch id was reused with different content",
            )
    try:
        outcome = store_mde_security_batch(
            batch,
            request.app.state,
            persist_raw=existing is None,
        )
    except Exception as exc:  # noqa: BLE001 - a retry repairs partial derived writes
        outcome = _failed_outcome("MDE alert", batch.batch_id, exc)
    return _ack(batch.batch_id, outcome, duplicate=existing is not None)


_MDVM_SOURCE = "microsoft-defender-vulnerability-management"


def _mdvm_asset_id(item: MdvmSoftwareVulnerability) -> str:
    digest = hashlib.sha256(
        f"{item.software_vendor}\0{item.software_name}\0{item.software_version}".encode()
    ).hexdigest()
    return f"mdvm-pkg-{digest}"


def _mdvm_evidence(item: MdvmSoftwareVulnerability) -> str:
    parts = [
        f"{item.software_vendor} {item.software_name} {item.software_version}",
    ]
    if item.exploitability_level:
        parts.append(f"exploitability={item.exploitability_level}")
    if item.recommended_security_update:
        parts.append(f"update={item.recommended_security_update}")
    if item.recommended_security_update_id:
        parts.append(f"update_id={item.recommended_security_update_id}")
    if item.first_seen_at:
        parts.append(f"first_seen={item.first_seen_at.isoformat()}")
    if item.last_seen_at:
        parts.append(f"last_seen={item.last_seen_at.isoformat()}")
    if item.evidence_truncated:
        parts.append("provider_evidence_truncated=true")
    return "; ".join(parts)[:4096]


def _mdvm_references(item: MdvmSoftwareVulnerability) -> list[str]:
    references: list[str] = []
    if item.recommended_security_update_url:
        references.append(item.recommended_security_update_url)
    if item.recommended_security_update_id:
        references.append(item.recommended_security_update_id)
    if item.recommendation_reference:
        references.append(item.recommendation_reference)
    if item.cve_id.upper().startswith("CVE-"):
        references.append(
            f"https://msrc.microsoft.com/update-guide/vulnerability/{item.cve_id.upper()}"
        )
    return list(dict.fromkeys(references))[:256]


def _derive_mdvm_snapshot(
    snapshot: MdvmDeviceSnapshot,
) -> tuple[AssetReport, DetectionResult]:
    packages: dict[str, Package] = {}
    findings: list[Vulnerability] = []
    for item in snapshot.vulnerabilities:
        asset_id = _mdvm_asset_id(item)
        packages.setdefault(
            asset_id,
            Package(
                asset_id=asset_id,
                name=f"{item.software_vendor}/{item.software_name}",
                version=item.software_version,
                source="mdvm",
            ),
        )
        findings.append(
            Vulnerability(
                vuln_id=item.cve_id,
                severity=item.severity,
                cvss_score=item.cvss_score,
                affected_asset_id=asset_id,
                source=_MDVM_SOURCE,
                evidence=_mdvm_evidence(item),
                references=_mdvm_references(item),
            )
        )
    package_rows = list(packages.values())
    os_name = " ".join(
        value for value in (snapshot.os_platform, snapshot.os_version) if value
    )
    report = AssetReport(
        report_id=snapshot.report_id,
        collected_at=snapshot.observed_at,
        scanner_version="mdvm-cloud-v1",
        host=HostInfo(
            host_id=snapshot.host_id,
            hostname=snapshot.device_name,
            os=os_name or "Microsoft Defender managed device",
            arch=snapshot.os_architecture,
        ),
        assets=package_rows,
        vulnerabilities=findings,
        detector_runs=[
            DetectorRun(
                detector=DetectorKind.DEFENDER,
                status=DetectorRunStatus.COMPLETE,
                finding_count=len(findings),
                reason="mdvm_cloud_snapshot",
            )
        ],
    )
    detection = DetectionResult(
        report_id=snapshot.report_id,
        host_id=snapshot.host_id,
        collected_at=snapshot.observed_at,
        ecosystem="MicrosoftDefenderVM",
        vulnerabilities=findings,
        detection_status=DetectionStatus.COMPLETE,
        status_reason=None,
        scanned_package_count=len(package_rows),
        coverage=[
            DetectionCoverage(
                detector=DetectorKind.DEFENDER,
                ecosystem="mdvm",
                status=CoverageStatus.COMPLETE,
                scanned_count=len(package_rows),
                finding_count=len(findings),
            )
        ],
    )
    return report, detection


def store_mdvm_vulnerability_batch(
    batch: MdvmVulnerabilityBatch,
    state: State,
    *,
    persist_raw: bool = True,
) -> _DerivedOutcome:
    """Persist one MDVM materialization and expose it through existing reports."""
    if persist_raw:
        state.mdvm_vulnerability_store.append(batch)
    records = 0
    for snapshot in batch.snapshots:
        report, detection = _derive_mdvm_snapshot(snapshot)
        if state.asset_report_store.find_one("report_id", report.report_id) is None:
            state.asset_report_store.append(report)
            records += 1
        if state.vulnerability_store.find_one("report_id", detection.report_id) is None:
            state.vulnerability_store.append(detection)
            records += 1
    return _DerivedOutcome(status="complete", records=records)


@router.post(
    "/mdvm-vulnerability-batch",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestAck,
)
async def ingest_mdvm_vulnerability_batch(
    batch: InboundMdvmVulnerabilityBatch,
    request: Request,
) -> IngestAck:
    """Idempotently accept a Form-materialized current MDVM device snapshot."""
    store = request.app.state.mdvm_vulnerability_store
    existing = store.find_one("batch_id", batch.batch_id)
    if existing is not None:
        stored = MdvmVulnerabilityBatch.model_validate(existing)
        if stored.model_dump(mode="json") != batch.model_dump(mode="json"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="MDVM batch id was reused with different content",
            )
    try:
        outcome = store_mdvm_vulnerability_batch(
            batch,
            request.app.state,
            persist_raw=existing is None,
        )
    except Exception as exc:  # noqa: BLE001 - retry repairs partial derived writes
        outcome = _failed_outcome("MDVM vulnerability", batch.batch_id, exc)
    return _ack(batch.batch_id, outcome, duplicate=existing is not None)
