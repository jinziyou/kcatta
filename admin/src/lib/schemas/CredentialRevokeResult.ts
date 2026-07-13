/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type Detail = string;
/**
 * True if local key files were removed
 */
export type KeyDeleted = boolean;
/**
 * True if a key line was removed from the target
 */
export type Revoked = boolean;

/**
 * Result of revoking a managed key (remote authorized_keys + local key files).
 */
export interface CredentialRevokeResult {
  detail?: Detail;
  key_deleted?: KeyDeleted;
  revoked: Revoked;
}
