"""Conservative Kali-to-Debian Security Tracker matching."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from functools import cmp_to_key

from ..schemas import (
    AssetReport,
    CoverageStatus,
    DetectionCoverage,
    DetectionStatus,
    DetectorKind,
    Package,
    Severity,
    Vulnerability,
)
from .debian_tracker import DebianTrackerAdvisory, DebianTrackerStore
from .debversion import dpkg_compare
from .limits import MAX_FINDING_BYTES, MAX_FINDINGS, FindingLimitState

SOURCE = "debian-security-tracker"

_URGENCY = {
    "unimportant": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "not yet assigned": Severity.MEDIUM,
}
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class KaliTrackerDetection:
    osv_report: AssetReport
    findings: list[Vulnerability]
    candidate_count: int
    verified_count: int
    unverified_count: int
    incomplete_count: int


def merge_kali_tracker_status(
    current: DetectionStatus,
    current_reason: str | None,
    result: KaliTrackerDetection,
    store: DebianTrackerStore,
    limit_state: FindingLimitState,
    *,
    osv_candidate_count: int,
) -> tuple[DetectionStatus, str | None]:
    """Merge tracker coverage without leaving a tracker-only run disabled."""
    if result.candidate_count == 0 or current == DetectionStatus.FAILED:
        return current, current_reason

    if not store.available:
        return DetectionStatus.PARTIAL, "debian_tracker_empty"
    if store.stale:
        return DetectionStatus.PARTIAL, "debian_tracker_stale"

    # An empty OSV store does not disable a run whose entire package inventory
    # belongs to the independently indexed Debian tracker. Mixed inventories
    # stay partial because their non-Kali packages were not checked.
    if current == DetectionStatus.DISABLED:
        current = DetectionStatus.COMPLETE if osv_candidate_count == 0 else DetectionStatus.PARTIAL
        current_reason = None if osv_candidate_count == 0 else current_reason

    if limit_state.truncated:
        return DetectionStatus.PARTIAL, limit_state.reason
    if result.incomplete_count:
        return DetectionStatus.PARTIAL, "debian_tracker_advisory_undetermined"
    if result.unverified_count:
        return DetectionStatus.PARTIAL, "some_kali_package_origins_unverified"
    return current, current_reason


def kali_tracker_coverage(
    result: KaliTrackerDetection,
    store: DebianTrackerStore,
    limit_state: FindingLimitState,
) -> DetectionCoverage | None:
    if result.candidate_count == 0:
        return None
    if not store.available:
        status = CoverageStatus.DISABLED
        reason = "debian_tracker_empty"
    elif store.stale:
        status = CoverageStatus.PARTIAL
        reason = "debian_tracker_stale"
    elif limit_state.truncated:
        status = CoverageStatus.PARTIAL
        reason = limit_state.reason
    elif result.incomplete_count:
        status = CoverageStatus.PARTIAL
        reason = "debian_tracker_advisory_undetermined"
    elif result.unverified_count:
        status = CoverageStatus.PARTIAL
        reason = "kali_package_origin_unverified"
    else:
        status = CoverageStatus.COMPLETE
        reason = None
    return DetectionCoverage(
        detector=DetectorKind.DEBIAN_TRACKER,
        ecosystem="Kali:rolling",
        status=status,
        scanned_count=result.verified_count,
        skipped_count=result.unverified_count,
        finding_count=len(result.findings),
        reason=reason,
    )


def _is_kali_package(report: AssetReport, package: Package) -> bool:
    ecosystem = package.ecosystem or ""
    return package.source == "dpkg" and (
        "kali" in report.host.os.lower() or ecosystem.split(":", 1)[0] == "Kali"
    )


def _affected(row: DebianTrackerAdvisory, source_version: str) -> bool | None:
    if row.status == "open":
        return True
    if row.status == "resolved":
        if not row.fixed_version or row.fixed_version == "0":
            return False
        return dpkg_compare(source_version, row.fixed_version) < 0
    if row.status == "undetermined":
        return None
    return None


def _severity(rows: list[DebianTrackerAdvisory]) -> Severity:
    values = [_URGENCY.get(row.urgency or "", Severity.MEDIUM) for row in rows]
    return max(values, key=_SEVERITY_RANK.__getitem__, default=Severity.MEDIUM)


def _binary_summary(packages: list[Package]) -> str:
    labels = sorted({f"{package.name} {package.version}" for package in packages})
    shown = ", ".join(labels[:5])
    if len(labels) > 5:
        shown += f", and {len(labels) - 5} more"
    return shown


def detect_kali_packages(
    report: AssetReport,
    store: DebianTrackerStore,
    *,
    max_findings: int = MAX_FINDINGS,
    max_bytes: int = MAX_FINDING_BYTES,
    limit_state: FindingLimitState | None = None,
) -> KaliTrackerDetection:
    """Match only dpkg source versions proven identical to a Debian repository.

    Kali forks and Kali-only packages do not share a trustworthy patch state
    with Debian even when names resemble each other. They remain explicit
    unverified coverage rather than being guessed vulnerable or clean.
    """
    candidates: list[Package] = []
    remaining_assets = []
    for asset in report.assets:
        if isinstance(asset, Package) and _is_kali_package(report, asset):
            candidates.append(asset)
        else:
            remaining_assets.append(asset)

    source_groups: dict[tuple[str | None, str, str], list[Package]] = defaultdict(list)
    for package in candidates:
        source_groups[
            (
                package.parent_asset_id,
                package.source_name or package.name,
                package.source_version or package.version,
            )
        ].append(package)

    findings: list[Vulnerability] = []
    verified = 0
    incomplete = 0
    consumed = 0
    for (parent_asset_id, source_name, source_version), packages in source_groups.items():
        rows = store.lookup(source_name, source_version)
        if not rows:
            continue
        # Coverage remains expressed in installed binary-package rows, while
        # source-level CVEs are emitted once per parent/source/version. A single
        # Debian source commonly builds many binaries; repeating the same CVE
        # for every output is noisy and falsely suggests binary-level precision.
        verified += len(packages)
        package = packages[0]
        grouped: dict[str, list[DebianTrackerAdvisory]] = defaultdict(list)
        for row in rows:
            grouped[row.advisory_id].append(row)
        for advisory_id, advisory_rows in grouped.items():
            affected_rows: list[DebianTrackerAdvisory] = []
            advisory_incomplete = False
            for row in advisory_rows:
                affected = _affected(row, source_version)
                if affected is True:
                    affected_rows.append(row)
                elif affected is None:
                    advisory_incomplete = True
            if advisory_incomplete:
                incomplete += 1
            if not affected_rows or not advisory_id.startswith("CVE-"):
                continue
            releases = sorted({row.release for row in affected_rows})
            fixed_versions = sorted(
                {
                    row.fixed_version
                    for row in affected_rows
                    if row.fixed_version and row.fixed_version != "0"
                },
                key=cmp_to_key(dpkg_compare),
            )
            evidence = (
                f"Debian source {source_name} {source_version} "
                f"(installed binaries: {_binary_summary(packages)}); "
                f"vulnerable in {', '.join(releases)}"
            )
            if fixed_versions:
                evidence += f" (fixed in {fixed_versions[0]})"
            finding = Vulnerability(
                vuln_id=advisory_id,
                severity=_severity(affected_rows),
                affected_asset_id=package.asset_id,
                parent_asset_id=parent_asset_id,
                source=SOURCE,
                evidence=evidence,
                references=[f"https://security-tracker.debian.org/tracker/{advisory_id}"],
            )
            encoded_bytes = len(finding.model_dump_json().encode("utf-8"))
            if len(findings) >= max_findings or consumed + encoded_bytes > max_bytes:
                if limit_state is not None:
                    limit_state.mark(
                        "debian_tracker_max_findings"
                        if len(findings) >= max_findings
                        else "debian_tracker_max_bytes"
                    )
                return KaliTrackerDetection(
                    osv_report=report.model_copy(update={"assets": remaining_assets}),
                    findings=findings,
                    candidate_count=len(candidates),
                    verified_count=verified,
                    unverified_count=len(candidates) - verified,
                    incomplete_count=incomplete,
                )
            findings.append(finding)
            consumed += encoded_bytes

    if incomplete and limit_state is not None:
        limit_state.mark_incomplete("debian_tracker_advisory_undetermined")
    return KaliTrackerDetection(
        osv_report=report.model_copy(update={"assets": remaining_assets}),
        findings=findings,
        candidate_count=len(candidates),
        verified_count=verified,
        unverified_count=len(candidates) - verified,
        incomplete_count=incomplete,
    )
