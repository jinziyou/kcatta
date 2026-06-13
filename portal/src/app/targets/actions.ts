"use server";

import { revalidatePath } from "next/cache";

import { FusionApiError, registerTarget } from "@/lib/api";
import type { CredentialMode, ScanTargetInput, Transport } from "@/lib/contracts";

export type RegisterResult = { ok: true } | { ok: false; error: string };

/**
 * Register a scan target. A one-time `password` (managed_key mode) is forwarded to
 * fusion to bootstrap a managed SSH key on the fusion host and is never persisted.
 * Runs on the server, so the fusion bearer token never reaches the browser.
 */
export async function registerTargetAction(input: ScanTargetInput): Promise<RegisterResult> {
  const name = input.name?.trim();
  const address = input.address?.trim();
  if (!name || !address) {
    return { ok: false, error: "名称与地址（user@host）为必填项" };
  }

  try {
    await registerTarget({
      name,
      address,
      port: Number.isFinite(input.port) && (input.port ?? 0) > 0 ? input.port : 22,
      transport: (input.transport ?? "ssh") as Transport,
      credential_mode: (input.credential_mode ?? "managed_key") as CredentialMode,
      identity_path: input.identity_path?.trim() || null,
      password: input.password?.trim() || null,
    });
  } catch (err) {
    return { ok: false, error: err instanceof FusionApiError ? err.message : String(err) };
  }

  revalidatePath("/targets");
  return { ok: true };
}
