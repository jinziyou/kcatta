/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

/**
 * When the source AssetReport was collected
 */
export type CollectedAt = string;
/**
 * Detection engines whose execution/coverage is surfaced to operators.
 *
 * This interface was referenced by `DetectionResult`'s JSON-Schema
 * via the `definition` "DetectorKind".
 */
export type DetectorKind = "osv" | "debian_tracker" | "defender" | "malware" | "posture" | "secret";
export type Ecosystem = string | null;
export type FindingCount = number;
export type Reason = string | null;
export type ScannedCount = number;
export type SkippedCount = number;
/**
 * Operator-facing status of one detector/scope in the coverage matrix.
 *
 * This interface was referenced by `DetectionResult`'s JSON-Schema
 * via the `definition` "CoverageStatus".
 */
export type CoverageStatus = "complete" | "partial" | "disabled" | "failed" | "unknown";
/**
 * Per-detector and per-ecosystem coverage; empty on legacy rows.
 *
 * @maxItems 256
 */
export type Coverage = DetectionCoverage[];
/**
 * Whether Analyzer completed vulnerability matching. A complete empty result is a verified zero-finding pass; disabled/partial/failed must not be presented as clean. The conservative partial default keeps pre-coverage historical records from being upgraded to complete.
 */
export type DetectionStatus = "complete" | "partial" | "disabled" | "failed";
/**
 * OSV ecosystem used for matching, e.g. 'Debian:12'
 */
export type Ecosystem1 = string;
export type HostId = string;
export type ReportId = string;
export type ScannedPackageCount = number;
/**
 * Stable operator-facing reason when coverage is not complete.
 */
export type StatusReason = string | null;
/**
 * True when generation limits omitted one or more findings.
 */
export type Truncated = boolean;
/**
 * Which item/byte ceiling caused findings to be omitted.
 */
export type TruncationReason = string | null;
/**
 * Packages with a resolved ecosystem that was absent from the atomic OSV sync manifest and therefore was not matched.
 */
export type UncoveredPackageCount = number;
/**
 * Packages skipped because no OSV ecosystem could be resolved.
 */
export type UnresolvedPackageCount = number;
/**
 * References Asset.asset_id from the same report
 */
export type AffectedAssetId = string;
export type CvssScore = number | null;
/**
 * Short, human-readable proof (e.g. matched package version)
 */
export type Evidence = string | null;
/**
 * Owning image/container asset_id when the affected package came from a nested image/container scan; lets CVEs be grouped per image/container. None for host-level findings.
 */
export type ParentAssetId = string | null;
/**
 * @maxItems 256
 */
export type References = string[];
/**
 * Severity level of a finding, ordered from informational to critical.
 *
 * This interface was referenced by `DetectionResult`'s JSON-Schema
 * via the `definition` "Severity".
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";
/**
 * Scanner / engine that produced the finding
 */
export type Source = string;
/**
 * CVE id, vendor advisory id, or scanner-local id (e.g. GHSA-..., CVE-2024-1234)
 */
export type VulnId = string;
/**
 * @maxItems 4096
 */
export type Vulnerabilities = Vulnerability[];
/**
 * Coverage state for Analyzer's vulnerability-detection pass.
 *
 * This interface was referenced by `DetectionResult`'s JSON-Schema
 * via the `definition` "DetectionStatus".
 */
export type DetectionStatus1 = "complete" | "partial" | "disabled" | "failed";

/**
 * analyzer-derived: vulnerability findings computed for one AssetReport.
 *
 * Produced by `analyzer.detect` after ingest (or on demand via `/detect`).
 * Carries enough provenance to attribute findings back to a host/report.
 */
export interface DetectionResult {
  collected_at: CollectedAt;
  coverage?: Coverage;
  detection_status?: DetectionStatus;
  ecosystem: Ecosystem1;
  host_id: HostId;
  report_id: ReportId;
  scanned_package_count?: ScannedPackageCount;
  status_reason?: StatusReason;
  truncated?: Truncated;
  truncation_reason?: TruncationReason;
  uncovered_package_count?: UncoveredPackageCount;
  unresolved_package_count?: UnresolvedPackageCount;
  vulnerabilities?: Vulnerabilities;
}
/**
 * One detector and optional ecosystem scope, with explicit zero-find evidence.
 *
 * This interface was referenced by `DetectionResult`'s JSON-Schema
 * via the `definition` "DetectionCoverage".
 */
export interface DetectionCoverage {
  detector: DetectorKind;
  ecosystem?: Ecosystem;
  finding_count?: FindingCount;
  reason?: Reason;
  scanned_count?: ScannedCount;
  skipped_count?: SkippedCount;
  status: CoverageStatus;
}
/**
 * A vulnerability finding affecting a specific asset on a host.
 *
 * This interface was referenced by `DetectionResult`'s JSON-Schema
 * via the `definition` "Vulnerability".
 */
export interface Vulnerability {
  affected_asset_id: AffectedAssetId;
  cvss_score?: CvssScore;
  evidence?: Evidence;
  parent_asset_id?: ParentAssetId;
  references?: References;
  severity: Severity;
  source: Source;
  vuln_id: VulnId;
}
