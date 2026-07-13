/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

/**
 * SSH/WinRM endpoint as user@host; for transport=local a free label (e.g. localhost)
 */
export type Address = string;
/**
 * Stable Analyzer host identity; defaults to target_id and is never taken from Agent telemetry
 */
export type CanonicalHostId = string | null;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CreatedAt = string;
/**
 * Where the target's durable credential lives on the Form host.
 */
export type CredentialMode = "managed_key" | "identity" | "none";
/**
 * server-side key path when credential_mode=identity
 */
export type IdentityPath = string | null;
export type Name = string;
export type Port = number;
export type TargetId = string;
/**
 * How Form reaches a target to deploy the agent.
 */
export type Transport = "ssh" | "winrm" | "local";
/**
 * Where the target's durable credential lives on the Form host.
 *
 * This interface was referenced by `ScanTarget`'s JSON-Schema
 * via the `definition` "CredentialMode".
 */
export type CredentialMode1 = "managed_key" | "identity" | "none";
/**
 * How Form reaches a target to deploy the agent.
 *
 * This interface was referenced by `ScanTarget`'s JSON-Schema
 * via the `definition` "Transport".
 */
export type Transport1 = "ssh" | "winrm" | "local";

/**
 * A registered scan target (no secret material).
 */
export interface ScanTarget {
  address: Address;
  canonical_host_id?: CanonicalHostId;
  created_at: CreatedAt;
  credential_mode?: CredentialMode;
  identity_path?: IdentityPath;
  name: Name;
  port?: Port;
  target_id: TargetId;
  transport?: Transport;
}
