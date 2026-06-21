"use server";

import { revalidatePath } from "next/cache";

import { AnalyzerApiError, revokeCredential, rotateCredential, testCredential } from "@/lib/api";

export type TestResult =
  | { ok: true; reachable: boolean; detail: string }
  | { ok: false; error: string };

export type MutationResult = { ok: true; detail: string } | { ok: false; error: string };

function errMessage(err: unknown): string {
  return err instanceof AnalyzerApiError ? err.message : String(err);
}

/**
 * Credential lifecycle actions. Run on the server so the analyzer bearer token
 * never reaches the browser; a one-time `password` (rotate/revoke fallback) is
 * forwarded to analyzer for a single SSH operation and never persisted.
 */
export async function testCredentialAction(credentialId: string): Promise<TestResult> {
  try {
    const r = await testCredential(credentialId);
    return { ok: true, reachable: r.ok, detail: r.detail };
  } catch (err) {
    return { ok: false, error: errMessage(err) };
  }
}

export async function rotateCredentialAction(
  credentialId: string,
  password?: string | null,
): Promise<MutationResult> {
  try {
    const cred = await rotateCredential(credentialId, password?.trim() || null);
    revalidatePath("/credentials");
    return { ok: true, detail: cred.fingerprint ? `已轮换 · 新指纹 ${cred.fingerprint}` : "已轮换" };
  } catch (err) {
    return { ok: false, error: errMessage(err) };
  }
}

export async function revokeCredentialAction(
  credentialId: string,
  password?: string | null,
): Promise<MutationResult> {
  try {
    const r = await revokeCredential(credentialId, password?.trim() || null);
    revalidatePath("/credentials");
    return { ok: true, detail: r.detail };
  } catch (err) {
    return { ok: false, error: errMessage(err) };
  }
}
