/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

/**
 * user@host this credential authenticates to
 */
export type Address = string;
export type CredentialId = string;
/**
 * Where the target's durable credential lives on the Form host.
 *
 * This interface was referenced by `CredentialInfo`'s JSON-Schema
 * via the `definition` "CredentialMode".
 */
export type CredentialMode = "managed_key" | "identity" | "none";
/**
 * whether the key/cert file is present on the Form host
 */
export type Exists = boolean;
/**
 * SHA256 fingerprint of the public key, when resolvable
 */
export type Fingerprint = string | null;
/**
 * server-side path of the key/cert on the Form host
 */
export type KeyPath = string;
export type Port = number;
export type TargetIds = string[];
export type TargetNames = string[];
/**
 * How Form reaches a target to deploy the agent.
 */
export type Transport = "ssh" | "winrm" | "local";
/**
 * How Form reaches a target to deploy the agent.
 *
 * This interface was referenced by `CredentialInfo`'s JSON-Schema
 * via the `definition` "Transport".
 */
export type Transport1 = "ssh" | "winrm" | "local";

/**
 * A durable access credential, summarized for management (no secret material).
 *
 * Derived from registered targets: managed keys are grouped by their logical
 * transport + ``user@host:port`` identity, so IDs remain stable if Form's
 * configuration root moves. ``target_ids`` lists every target that shares it.
 */
export interface CredentialInfo {
  address: Address;
  credential_id: CredentialId;
  credential_mode: CredentialMode;
  exists: Exists;
  fingerprint?: Fingerprint;
  key_path: KeyPath;
  port?: Port;
  target_ids?: TargetIds;
  target_names?: TargetNames;
  transport?: Transport;
}
