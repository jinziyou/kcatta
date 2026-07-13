"use server";

import { FormApiError, cancelScan, getScan, retryScan, triggerScan } from "@/lib/api";
import type { ScanCapability, ScanJob, ScanJobOptions } from "@/lib/contracts";

export interface TriggerInput {
  target_id: string;
  capability: ScanCapability;
  options: Partial<ScanJobOptions>;
  request_id: string;
}

export type TriggerResult = { ok: true; jobId: string } | { ok: false; error: string };

/**
 * Trigger (下发) a scan against a registered target. Runs on the server so the
 * Form bearer token never reaches the browser; returns the new job id (or an
 * error message) for the client to navigate / toast.
 */
export async function triggerScanAction(input: TriggerInput): Promise<TriggerResult> {
  if (!input.target_id) return { ok: false, error: "请选择扫描目标" };
  try {
    const job: ScanJob = await triggerScan(
      {
        target_id: input.target_id,
        capability: input.capability,
        options: input.options,
      },
      input.request_id,
    );
    return { ok: true, jobId: job.job_id };
  } catch (err) {
    return { ok: false, error: err instanceof FormApiError ? err.message : String(err) };
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

export type ScanActionResult =
  | { ok: true; job: ScanJob }
  | { ok: false; error: string };

async function runJobAction(action: () => Promise<ScanJob>): Promise<ScanActionResult> {
  try {
    return { ok: true, job: await action() };
  } catch (err) {
    return { ok: false, error: err instanceof FormApiError ? err.message : String(err) };
  }
}

/** Server-side cancellation keeps the Form control token out of the browser. */
export async function cancelScanAction(jobId: string): Promise<ScanActionResult> {
  return runJobAction(() => cancelScan(jobId));
}

/** Requeue a terminal job after an operator explicitly asks for another attempt. */
export async function retryScanAction(jobId: string): Promise<ScanActionResult> {
  return runJobAction(() => retryScan(jobId));
}
