"use server";

import { revalidatePath } from "next/cache";

import { FusionApiError, registerTarget } from "@/lib/api";
import type { CredentialMode, Transport } from "@/lib/contracts";

export type ActionResult = { ok: boolean; error?: string };

function field(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

/**
 * Register a scan target. A one-time `password` (managed_key mode) is forwarded to
 * fusion to bootstrap a managed SSH key on the fusion host; it is never stored.
 * Runs on the server, so the fusion bearer token never reaches the browser.
 */
export async function registerTargetAction(
  _prev: ActionResult | null,
  formData: FormData,
): Promise<ActionResult> {
  const name = field(formData, "name");
  const address = field(formData, "address");
  if (!name || !address) {
    return { ok: false, error: "name and address (user@host) are required" };
  }

  const port = Number(field(formData, "port"));
  try {
    await registerTarget({
      name,
      address,
      port: Number.isFinite(port) && port > 0 ? port : 22,
      transport: (field(formData, "transport") || "ssh") as Transport,
      credential_mode: (field(formData, "credential_mode") || "managed_key") as CredentialMode,
      identity_path: field(formData, "identity_path") || null,
      password: field(formData, "password") || null,
    });
  } catch (err) {
    return { ok: false, error: err instanceof FusionApiError ? err.message : String(err) };
  }

  revalidatePath("/targets");
  return { ok: true };
}
