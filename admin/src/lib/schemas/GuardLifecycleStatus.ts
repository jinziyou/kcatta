/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type Address = string;
export type Alive = boolean;
export type Detail = string;
export type Pid = string | null;
/**
 * systemd | process | unknown
 */
export type Supervisor = string;
export type TargetId = string;

/**
 * Liveness of a target's resident guard daemon (for the 常驻 management view).
 */
export interface GuardLifecycleStatus {
  address: Address;
  alive: Alive;
  detail?: Detail;
  pid?: Pid;
  supervisor: Supervisor;
  target_id: TargetId;
}
