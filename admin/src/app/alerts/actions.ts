"use server";

import { FormApiError, triageAlert, type AlertTriageInput } from "@/lib/api";

export type TriageResult = { ok: true } | { ok: false; error: string };

/**
 * Apply a triage update (status / assignee / note / suppress) to an alert. Runs
 * on the server so the Form bearer token never reaches the browser; the
 * client refreshes the route on success to re-render with the new state.
 */
export async function triageAlertAction(
  alertKey: string,
  input: AlertTriageInput,
): Promise<TriageResult> {
  if (!alertKey) return { ok: false, error: "缺少 alert_key" };
  try {
    await triageAlert(alertKey, input);
  } catch (err) {
    return { ok: false, error: err instanceof FormApiError ? err.message : String(err) };
  }
  return { ok: true };
}
