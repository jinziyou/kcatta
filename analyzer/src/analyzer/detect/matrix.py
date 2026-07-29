"""Build explicit detector/ecosystem coverage without inferring clean from zero."""

from __future__ import annotations

import hashlib
from collections import Counter

from ..schemas import (
    AssetReport,
    CoverageStatus,
    DetectionCoverage,
    DetectionStatus,
    DetectorKind,
    Package,
    Vulnerability,
)
from .coverage import EcosystemCoverage, PackageCoverage

_SCANNER_KINDS = (
    DetectorKind.DEFENDER,
    DetectorKind.MALWARE,
    DetectorKind.POSTURE,
    DetectorKind.SECRET,
)
_SOURCE_KIND = {
    "microsoft-defender": DetectorKind.DEFENDER,
    "microsoft-defender-event": DetectorKind.DEFENDER,
    "kcatta-malware": DetectorKind.MALWARE,
    "clamav": DetectorKind.MALWARE,
    "posture": DetectorKind.POSTURE,
    "secret": DetectorKind.SECRET,
}
# DetectionResult permits 256 rows. Reserve four producer detector rows, a
# grouped OSV row when exact ecosystems overflow, and a Debian Tracker row
# only when the current report actually needs one.
_MAX_OSV_ROWS = 250


def _scope(value: str | None) -> str | None:
    if value is None or len(value) <= 256:
        return value
    digest = hashlib.sha256(value.encode()).hexdigest()
    return f"{value[:183]}~sha256:{digest}"


def _osv_row(
    item: EcosystemCoverage,
    *,
    finding_count: int,
    store_available: bool,
    sync_known: bool,
    detection_status: DetectionStatus,
    status_reason: str | None,
    incomplete_reason: str | None,
) -> DetectionCoverage:
    scanned = item.covered
    skipped = item.total - item.covered
    if not store_available:
        status = CoverageStatus.DISABLED
        reason = "osv_store_empty"
        scanned = 0
        skipped = item.total
    elif detection_status == DetectionStatus.FAILED:
        status = CoverageStatus.FAILED
        reason = status_reason or "osv_detection_failed"
    elif item.ecosystem is None:
        status = CoverageStatus.PARTIAL
        reason = "ecosystem_unresolved"
    elif item.unsupported:
        status = CoverageStatus.PARTIAL
        reason = "osv_ecosystem_unsupported"
    elif item.uncovered:
        status = CoverageStatus.PARTIAL
        reason = "osv_ecosystem_not_synced"
    elif not sync_known:
        status = CoverageStatus.PARTIAL
        reason = "osv_sync_incomplete"
    elif incomplete_reason:
        status = CoverageStatus.PARTIAL
        reason = incomplete_reason
    else:
        status = CoverageStatus.COMPLETE
        reason = None
    return DetectionCoverage(
        detector=DetectorKind.OSV,
        ecosystem=_scope(item.ecosystem),
        status=status,
        scanned_count=scanned,
        skipped_count=skipped,
        finding_count=finding_count,
        reason=reason,
    )


def coverage_matrix(
    report: AssetReport,
    package_coverage: PackageCoverage,
    osv_findings: list[Vulnerability],
    scanner_findings: list[Vulnerability],
    *,
    default_ecosystem: str | None,
    osv_store_available: bool,
    osv_sync_known: bool,
    detection_status: DetectionStatus,
    status_reason: str | None,
    osv_incomplete_reason: str | None = None,
    scanner_incomplete_reason: str | None = None,
    debian_tracker_coverage: DetectionCoverage | None = None,
) -> list[DetectionCoverage]:
    """Return bounded, truthful OSV scopes plus Agent detector execution rows."""

    package_ecosystems = {
        package.asset_id: package.ecosystem or default_ecosystem
        for package in report.assets
        if isinstance(package, Package)
    }
    osv_counts: Counter[str | None] = Counter(
        package_ecosystems.get(finding.affected_asset_id) for finding in osv_findings
    )
    ecosystem_rows = list(package_coverage.ecosystems)
    if not ecosystem_rows:
        ecosystem_rows = [EcosystemCoverage(None, 0, 0, 0, 0, 0)]
    max_osv_rows = _MAX_OSV_ROWS if debian_tracker_coverage is not None else _MAX_OSV_ROWS + 1
    rows = [
        _osv_row(
            item,
            finding_count=osv_counts[item.ecosystem],
            store_available=osv_store_available,
            sync_known=osv_sync_known,
            detection_status=detection_status,
            status_reason=status_reason,
            incomplete_reason=osv_incomplete_reason,
        )
        for item in ecosystem_rows[:max_osv_rows]
    ]
    if len(ecosystem_rows) > max_osv_rows:
        omitted = ecosystem_rows[max_osv_rows:]
        rows.append(
            DetectionCoverage(
                detector=DetectorKind.OSV,
                ecosystem="other",
                status=CoverageStatus.PARTIAL,
                scanned_count=sum(item.covered for item in omitted),
                skipped_count=sum(item.total - item.covered for item in omitted),
                finding_count=sum(osv_counts[item.ecosystem] for item in omitted),
                reason="coverage_matrix_grouped",
            )
        )

    if debian_tracker_coverage is not None:
        rows.append(debian_tracker_coverage)

    actual_counts: Counter[DetectorKind] = Counter(
        kind
        for finding in scanner_findings
        if (kind := _SOURCE_KIND.get(finding.source)) is not None
    )
    declared = None
    if report.detector_runs is not None:
        declared = {
            run.detector: run for run in report.detector_runs if run.detector != DetectorKind.OSV
        }
    for kind in _SCANNER_KINDS:
        actual = actual_counts[kind]
        run = declared.get(kind) if declared is not None else None
        if declared is None:
            run_status = CoverageStatus.UNKNOWN
            reason = "producer_detector_coverage_unknown"
        elif run is None:
            run_status = CoverageStatus.DISABLED
            reason = "detector_not_enabled"
        else:
            run_status = CoverageStatus(run.status.value)
            reason = run.reason
            if run.finding_count != actual:
                run_status = CoverageStatus.PARTIAL
                reason = "detector_finding_count_mismatch"
            if scanner_incomplete_reason and run_status == CoverageStatus.COMPLETE:
                run_status = CoverageStatus.PARTIAL
                reason = scanner_incomplete_reason
        rows.append(
            DetectionCoverage(
                detector=kind,
                status=run_status,
                finding_count=actual,
                reason=reason,
            )
        )
    return rows
