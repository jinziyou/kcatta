"use server";

import { redirect } from "next/navigation";

import { FusionApiError, getScan, triggerScan } from "@/lib/api";
import type { ScanCapability, ScanJob } from "@/lib/contracts";

export type TriggerResult = { ok: boolean; error?: string };

function field(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

/**
 * Trigger a scan against a registered target, then redirect to its detail page.
 * Runs on the server (fusion token stays server-side). On error, returns a result
 * the form surfaces inline instead of navigating.
 */
export async function triggerScanAction(
  _prev: TriggerResult | null,
  formData: FormData,
): Promise<TriggerResult> {
  const target_id = field(formData, "target_id");
  if (!target_id) {
    return { ok: false, error: "select a target" };
  }
  const capability = (field(formData, "capability") || "host") as ScanCapability;

  let job: ScanJob;
  try {
    job = await triggerScan({
      target_id,
      capability,
      options: {
        scan_target: field(formData, "scan_target") || "all",
        malware: formData.get("malware") === "on",
        pcap: formData.get("pcap") === "on",
      },
    });
  } catch (err) {
    return { ok: false, error: err instanceof FusionApiError ? err.message : String(err) };
  }

  // Success: navigate to the live job view (redirect throws a control-flow signal).
  redirect(`/scans/${job.job_id}`);
}

/** Polled by the scan-detail client component until the job reaches a terminal state. */
export async function pollScanAction(jobId: string): Promise<ScanJob | null> {
  try {
    return await getScan(jobId);
  } catch {
    return null;
  }
}
