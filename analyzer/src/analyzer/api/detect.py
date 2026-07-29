"""On-demand vulnerability detection endpoint.

Accepts an `AssetReport` and matches its packages against the OSV store
loaded at app startup, returning a `DetectionResult`. Stateless: it neither
reads the ingest stores nor persists results, so it composes cleanly with
`/ingest/asset-report` (ingest to store + auto-detect, this for ad-hoc runs).
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BeforeValidator

from ..detect import (
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
from ..schemas import AssetReport, DetectionResult, DetectionStatus

router = APIRouter(prefix="/detect", tags=["detect"])


def _strict_report(value: Any) -> AssetReport:
    """Reject ad-hoc input fields that would otherwise vanish before detection."""
    return AssetReport.model_validate(value, extra="forbid")


InboundAssetReport = Annotated[AssetReport, BeforeValidator(_strict_report)]


@router.post("/asset-report", response_model=DetectionResult)
async def detect_asset_report(report: InboundAssetReport, request: Request) -> DetectionResult:
    """Match an asset report against the OSV store and return findings without persisting."""
    scanner_limit = FindingLimitState()
    malware = scanner_findings(report, limit_state=scanner_limit)
    ecosystem = resolve_ecosystem(report, request.app.state.osv_ecosystem) or ""
    tracker_limit = FindingLimitState()
    tracker_store = request.app.state.debian_tracker_store
    tracker = detect_kali_packages(
        report,
        tracker_store,
        limit_state=tracker_limit,
    )
    coverage = package_coverage(
        tracker.osv_report,
        ecosystem or None,
        getattr(request.app.state, "osv_synced_ecosystems", None),
    )
    detection_status = DetectionStatus.COMPLETE
    status_reason: str | None = None
    scanned_package_count = 0

    osv_vulns: list = []
    store = request.app.state.osv_store
    osv_limit = FindingLimitState()
    if store.record_count <= 0:
        detection_status = DetectionStatus.DISABLED
        status_reason = "osv_store_empty"
    else:
        if coverage.total == 0 and tracker.candidate_count == 0:
            detection_status = DetectionStatus.PARTIAL
            status_reason = "no_package_inventory"
        elif getattr(request.app.state, "osv_synced_ecosystems", None) is None:
            detection_status = DetectionStatus.PARTIAL
            status_reason = "osv_sync_incomplete"
        if coverage.total and coverage.resolved == 0:
            # Preserve the endpoint's actionable 422 for a wholly unresolvable
            # ad-hoc request with no scanner-native evidence to return.
            if not malware:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"cannot derive OSV ecosystem from host.os {report.host.os!r}; "
                        "set ANALYZER_OSV_ECOSYSTEM or Package.ecosystem"
                    ),
                )
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
                osv_vulns = detect_report(
                    coverage.detection_report,
                    store,
                    ecosystem or None,
                    limit_state=osv_limit,
                )
            except Exception:  # noqa: BLE001 - return scanner evidence + explicit status
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
    return DetectionResult(
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
        coverage=coverage_matrix(
            report,
            coverage,
            osv_vulns,
            malware,
            default_ecosystem=ecosystem or None,
            osv_store_available=store.record_count > 0,
            osv_sync_known=getattr(request.app.state, "osv_synced_ecosystems", None) is not None,
            detection_status=detection_status,
            status_reason=status_reason,
            osv_incomplete_reason=osv_limit.incomplete_reason or osv_limit.reason,
            scanner_incomplete_reason=(scanner_limit.incomplete_reason or scanner_limit.reason),
            debian_tracker_coverage=kali_tracker_coverage(
                tracker,
                tracker_store,
                tracker_limit,
            ),
        ),
    )
