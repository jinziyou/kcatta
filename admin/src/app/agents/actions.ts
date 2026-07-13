"use server";

import { revalidatePath } from "next/cache";

import { FormApiError, revokeAgentIdentity } from "@/lib/api";

export type RevokeAgentIdentityResult =
  | { ok: true; detail: string }
  | { ok: false; error: string };

function errMessage(err: unknown): string {
  return err instanceof FormApiError ? err.message : String(err);
}

/**
 * Revoke the stable identity, not a selectable certificate generation.
 * This remains a Server Action so the Form bearer token never reaches the
 * browser; the API client hard-codes generation=null for whole revocation.
 */
export async function revokeAgentIdentityAction(
  agentId: string,
): Promise<RevokeAgentIdentityResult> {
  try {
    const identity = await revokeAgentIdentity(agentId);
    revalidatePath("/agents");
    return {
      ok: true,
      detail: "Agent " + identity.agent_id + " 及其全部证书代次已吊销",
    };
  } catch (err) {
    return { ok: false, error: errMessage(err) };
  }
}
