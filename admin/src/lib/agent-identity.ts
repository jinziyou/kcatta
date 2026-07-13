/**
 * Temporary TypeScript mirror of Form's public AgentIdentity schema.
 *
 * This module intentionally contains metadata only.  In particular, the
 * one-time AgentCertificateBundle (including private_key_pem) is not part of
 * the Admin contract and must never cross the Server Component boundary.
 * Replace this mirror with the generated schema export after Form publishes
 * AgentIdentity.schema.json.
 */

/** Telemetry families this identity is authorized to submit. */
export type AgentScope = "asset-report" | "trace-batch" | "guard-event";

/** Durable lifecycle state of a stable agent identity. */
export type AgentIdentityState = "active" | "revoked";

/** Lifecycle state of one immutable client-certificate generation. */
export type AgentCertificateState = "staged" | "active" | "retired" | "revoked";

/** Non-secret metadata for an issued client certificate. */
export interface AgentCertificate {
  agent_id: string;
  generation: number;
  serial_number: string;
  cert_sha256: string;
  spki_sha256: string;
  state: AgentCertificateState;
  not_before: string;
  not_after: string;
  created_at: string;
  activated_at?: string | null;
  retired_at?: string | null;
  overlap_until?: string | null;
  revoked_at?: string | null;
}

/** Stable server-owned binding between a target, host, scopes, and agent id. */
export interface AgentIdentity {
  agent_id: string;
  target_id: string;
  canonical_host_id: string;
  scopes: AgentScope[];
  state: AgentIdentityState;
  generation: number;
  created_at: string;
  updated_at: string;
  revoked_at?: string | null;
  certificates: AgentCertificate[];
}
