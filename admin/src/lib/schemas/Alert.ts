/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type AlertId = string;
export type AlertKey = string | null;
export type Assignee = string | null;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CreatedAt = string;
export type Description = string;
/**
 * True when lifecycle aggregation found more related evidence IDs than the bounded wire lists can retain.
 */
export type EvidenceTruncated = boolean;
export type LastSeen = string | null;
export type Note = string | null;
export type OccurrenceCount = number;
/**
 * @maxItems 256
 */
export type RelatedAssetIds = string[];
/**
 * @maxItems 256
 */
export type RelatedTraceIds = string[];
/**
 * @maxItems 256
 */
export type RelatedVulnIds = string[];
/**
 * Risk score, 0-100
 */
export type Score = number;
/**
 * Severity level of a finding, ordered from informational to critical.
 *
 * This interface was referenced by `Alert`'s JSON-Schema
 * via the `definition` "Severity".
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";
/**
 * Lifecycle state of an alert as it is triaged.
 */
export type AlertStatus = "open" | "acknowledged" | "closed";
export type Suppressed = boolean;
export type Title = string;
export type UpdatedAt = string | null;
/**
 * Lifecycle state of an alert as it is triaged.
 *
 * This interface was referenced by `Alert`'s JSON-Schema
 * via the `definition` "AlertStatus".
 */
export type AlertStatus1 = "open" | "acknowledged" | "closed";

/**
 * A correlated security alert linking related assets, vulnerabilities, and events.
 */
export interface Alert {
  alert_id: AlertId;
  alert_key?: AlertKey;
  assignee?: Assignee;
  created_at: CreatedAt;
  description: Description;
  evidence_truncated?: EvidenceTruncated;
  last_seen?: LastSeen;
  note?: Note;
  occurrence_count?: OccurrenceCount;
  related_asset_ids?: RelatedAssetIds;
  related_trace_ids?: RelatedTraceIds;
  related_vuln_ids?: RelatedVulnIds;
  score: Score;
  severity: Severity;
  status?: AlertStatus;
  suppressed?: Suppressed;
  title: Title;
  updated_at?: UpdatedAt;
}
