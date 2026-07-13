/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type Address = string;
/**
 * Optional stable host id; Form assigns target_id when omitted
 */
export type CanonicalHostId = string | null;
/**
 * Where the target's durable credential lives on the Form host.
 */
export type CredentialMode = "managed_key" | "identity" | "none";
export type IdentityPath = string | null;
export type Name = string;
/**
 * one-time password to bootstrap a managed SSH key; never persisted
 */
export type Password = string | null;
export type Port = number;
/**
 * How Form reaches a target to deploy the agent.
 */
export type Transport = "ssh" | "winrm" | "local";
/**
 * Where the target's durable credential lives on the Form host.
 *
 * This interface was referenced by `ScanTargetInput`'s JSON-Schema
 * via the `definition` "CredentialMode".
 */
export type CredentialMode1 = "managed_key" | "identity" | "none";
/**
 * How Form reaches a target to deploy the agent.
 *
 * This interface was referenced by `ScanTargetInput`'s JSON-Schema
 * via the `definition` "Transport".
 */
export type Transport1 = "ssh" | "winrm" | "local";

/**
 * Registration payload. `password` (if any) is one-time bootstrap only.
 */
export interface ScanTargetInput {
  address: Address;
  canonical_host_id?: CanonicalHostId;
  credential_mode?: CredentialMode;
  identity_path?: IdentityPath;
  name: Name;
  password?: Password;
  port?: Port;
  transport?: Transport;
}
