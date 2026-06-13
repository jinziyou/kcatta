"use server";

import { FusionApiError, getScan, triggerScan } from "@/lib/api";
import type { ScanCapability, ScanJob, ScanJobOptions } from "@/lib/contracts";

export interface TriggerInput {
  target_id: string;
  capability: ScanCapability;
  options: Partial<ScanJobOptions>;
}

export type TriggerResult = { ok: true; jobId: string } | { ok: false; error: string };

/**
 * Trigger (下发) a scan against a registered target. Runs on the server so the
 * fusion bearer token never reaches the browser; returns the new job id (or an
 * error message) for the client to navigate / toast.
 */
export async function triggerScanAction(input: TriggerInput): Promise<TriggerResult> {
  if (!input.target_id) return { ok: false, error: "请选择扫描目标" };
  try {
    const job: ScanJob = await triggerScan({
      target_id: input.target_id,
      capability: input.capability,
      options: input.options,
    });
    return { ok: true, jobId: job.job_id };
  } catch (err) {
    return { ok: false, error: err instanceof FusionApiError ? err.message : String(err) };
  }
}

/** Polled by the job monitor until the job reaches a terminal state. */
export async function pollScanAction(jobId: string): Promise<ScanJob | null> {
  try {
    return await getScan(jobId);
  } catch {
    return null;
  }
}
