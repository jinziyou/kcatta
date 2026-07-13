/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type Detail = string;
export type Ok = boolean;

/**
 * Result of probing whether a credential can still authenticate.
 */
export interface CredentialTestResult {
  detail?: Detail;
  ok: Ok;
}
