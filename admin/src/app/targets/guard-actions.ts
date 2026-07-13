"use server";

import { FormApiError, getGuardStatus, stopGuard } from "@/lib/api";
import type { GuardLifecycleStatus } from "@/lib/contracts";

export type GuardResult =
  | { ok: true; status: GuardLifecycleStatus }
  | { ok: false; error: string };

function errMessage(err: unknown): string {
  return err instanceof FormApiError ? err.message : String(err);
}

/** Probe a target's resident guard daemon. Runs server-side (token stays off-browser). */
export async function guardStatusAction(targetId: string): Promise<GuardResult> {
  try {
    return { ok: true, status: await getGuardStatus(targetId) };
  } catch (err) {
    return { ok: false, error: errMessage(err) };
  }
}

/** Stop + uninstall a target's resident guard daemon. */
export async function stopGuardAction(targetId: string): Promise<GuardResult> {
  try {
    return { ok: true, status: await stopGuard(targetId) };
  } catch (err) {
    return { ok: false, error: errMessage(err) };
  }
}
