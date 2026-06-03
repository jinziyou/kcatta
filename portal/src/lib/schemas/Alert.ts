/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (derived from Pydantic models).
 * Regenerate: `pnpm generate:contracts` from portal/
 */

export type AlertId = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CreatedAt = string;
export type Description = string;
export type RelatedAssetIds = string[];
export type RelatedFlowIds = string[];
export type RelatedVulnIds = string[];
/**
 * Risk score, 0-100
 */
export type Score = number;
/**
 * This interface was referenced by `Alert`'s JSON-Schema
 * via the `definition` "Severity".
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "closed";
export type Title = string;
export type UpdatedAt = string | null;
/**
 * This interface was referenced by `Alert`'s JSON-Schema
 * via the `definition` "AlertStatus".
 */
export type AlertStatus1 = "open" | "acknowledged" | "closed";

export interface Alert {
  alert_id: AlertId;
  created_at: CreatedAt;
  description: Description;
  related_asset_ids?: RelatedAssetIds;
  related_flow_ids?: RelatedFlowIds;
  related_vuln_ids?: RelatedVulnIds;
  score: Score;
  severity: Severity;
  status?: AlertStatus;
  title: Title;
  updated_at?: UpdatedAt;
}

