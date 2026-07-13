/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type EntryHost = string;
export type GeneratedAt = string | null;
/**
 * The goal fact reached, e.g. access.admin
 */
export type Goal = string;
export type GoalHost = string;
export type PathId = string;
export type RelatedAssetIds = string[];
export type RelatedVulnIds = string[];
export type Score = number;
/**
 * Severity level of a finding, ordered from informational to critical.
 *
 * This interface was referenced by `AttackPath`'s JSON-Schema
 * via the `definition` "Severity".
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type HostId = string;
export type HostLabel = string;
export type ModuleId = string;
export type PostconditionsGained = string[];
export type PreconditionsMet = string[];
export type Tactic = string;
export type TechniqueId = string;
export type Steps = AttackPathStep[];

/**
 * analyzer-derived: a posture-grounded chain from an entry point to a goal.
 *
 * Deterministic — re-deriving from the same posture + capability graph yields
 * the same `path_id` and steps, so the read endpoint is idempotent.
 */
export interface AttackPath {
  entry_host: EntryHost;
  generated_at?: GeneratedAt;
  goal: Goal;
  goal_host: GoalHost;
  path_id: PathId;
  related_asset_ids?: RelatedAssetIds;
  related_vuln_ids?: RelatedVulnIds;
  score: Score;
  severity: Severity;
  steps?: Steps;
}
/**
 * One hop of a predicted attack path: a technique applied on a host.
 *
 * This interface was referenced by `AttackPath`'s JSON-Schema
 * via the `definition` "AttackPathStep".
 */
export interface AttackPathStep {
  host_id: HostId;
  host_label?: HostLabel;
  module_id: ModuleId;
  postconditions_gained?: PostconditionsGained;
  preconditions_met?: PreconditionsMet;
  tactic?: Tactic;
  technique_id?: TechniqueId;
}
