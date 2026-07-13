/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

/**
 * one-time password used only when the current managed key can no longer authenticate (rotate/revoke fallback); never persisted
 */
export type Password = string | null;

/**
 * Body for rotate/revoke. ``password`` is a one-time SSH fallback, never persisted.
 */
export interface CredentialActionRequest {
  password?: Password;
}
