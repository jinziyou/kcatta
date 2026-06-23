/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: analyzer/schemas-json/*.schema.json (derived from Pydantic models).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

/**
 * When the source AssetReport was collected
 */
export type CollectedAt = string;
/**
 * OSV ecosystem used for matching, e.g. 'Debian:12'
 */
export type Ecosystem = string;
export type HostId = string;
export type ReportId = string;
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
export type Vulnerabilities = Vulnerability[];

/**
 * analyzer-derived: vulnerability findings computed for one AssetReport.
 *
 * Produced by `analyzer.detect` after ingest (or on demand via `/detect`).
 * Carries enough provenance to attribute findings back to a host/report.
 */
export interface DetectionResult {
  collected_at: CollectedAt;
  ecosystem: Ecosystem;
  host_id: HostId;
  report_id: ReportId;
  vulnerabilities?: Vulnerabilities;
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

