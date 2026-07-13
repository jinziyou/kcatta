/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type AgentId = string;
export type CanonicalHostId = string;
export type ActivatedAt = string | null;
export type AgentId1 = string;
export type CertSha256 = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CreatedAt = string;
export type Generation = number;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type NotAfter = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type NotBefore = string;
/**
 * Retired certificate remains valid through this rotation overlap instant
 */
export type OverlapUntil = string | null;
export type RetiredAt = string | null;
export type RevokedAt = string | null;
export type SerialNumber = string;
export type SpkiSha256 = string;
/**
 * Lifecycle state of one immutable certificate generation.
 *
 * This interface was referenced by `AgentIdentity`'s JSON-Schema
 * via the `definition` "AgentCertificateState".
 */
export type AgentCertificateState = "staged" | "active" | "retired" | "revoked";
export type Certificates = AgentCertificate[];
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CreatedAt1 = string;
export type Generation1 = number;
export type RevokedAt1 = string | null;
/**
 * @minItems 1
 */
export type Scopes = [AgentScope, ...AgentScope[]];
/**
 * Telemetry families an agent identity may submit.
 *
 * This interface was referenced by `AgentIdentity`'s JSON-Schema
 * via the `definition` "AgentScope".
 */
export type AgentScope = "asset-report" | "trace-batch" | "guard-event";
/**
 * Durable state of an agent identity.
 */
export type AgentIdentityState = "active" | "revoked";
export type TargetId = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type UpdatedAt = string;
/**
 * Durable state of an agent identity.
 *
 * This interface was referenced by `AgentIdentity`'s JSON-Schema
 * via the `definition` "AgentIdentityState".
 */
export type AgentIdentityState1 = "active" | "revoked";

/**
 * Stable server-owned binding between a target, host, scopes, and agent id.
 */
export interface AgentIdentity {
  agent_id: AgentId;
  canonical_host_id: CanonicalHostId;
  certificates?: Certificates;
  created_at: CreatedAt1;
  generation?: Generation1;
  revoked_at?: RevokedAt1;
  scopes: Scopes;
  state?: AgentIdentityState;
  target_id: TargetId;
  updated_at: UpdatedAt;
}
/**
 * Non-secret metadata retained for one issued client certificate.
 *
 * This interface was referenced by `AgentIdentity`'s JSON-Schema
 * via the `definition` "AgentCertificate".
 */
export interface AgentCertificate {
  activated_at?: ActivatedAt;
  agent_id: AgentId1;
  cert_sha256: CertSha256;
  created_at: CreatedAt;
  generation: Generation;
  not_after: NotAfter;
  not_before: NotBefore;
  overlap_until?: OverlapUntil;
  retired_at?: RetiredAt;
  revoked_at?: RevokedAt;
  serial_number: SerialNumber;
  spki_sha256: SpkiSha256;
  state: AgentCertificateState;
}
