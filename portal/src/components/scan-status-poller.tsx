"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { pollScanAction } from "@/app/scans/actions";
import { Badge } from "@/components/ui/badge";
import type { ScanJob, ScanJobState } from "@/lib/contracts";

const TERMINAL: ScanJobState[] = ["succeeded", "failed"];

const STATE_VARIANT: Record<ScanJobState, "outline" | "secondary" | "default" | "destructive"> = {
  pending: "outline",
  running: "secondary",
  succeeded: "default",
  failed: "destructive",
};

/** Live status + result for a scan job; polls until the job reaches a terminal state. */
export function ScanStatusPoller({ initial }: { initial: ScanJob }) {
  const [job, setJob] = useState<ScanJob>(initial);

  useEffect(() => {
    if (TERMINAL.includes(job.state)) return;
    const id = setInterval(async () => {
      const next = await pollScanAction(job.job_id);
      if (next) setJob(next);
    }, 2500);
    return () => clearInterval(id);
  }, [job.state, job.job_id]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <Badge variant={STATE_VARIANT[job.state]}>{job.state}</Badge>
        {!TERMINAL.includes(job.state) && (
          <span className="text-muted-foreground text-xs">polling every 2.5s…</span>
        )}
      </div>
      {job.error && <p className="text-destructive text-sm">{job.error}</p>}
      {job.result && <ResultLinks job={job} />}
    </div>
  );
}

function ResultLinks({ job }: { job: ScanJob }) {
  const result = job.result;
  if (!result) return null;

  if (result.kind === "host" && result.report_id) {
    return (
      <div className="flex flex-wrap gap-3 text-sm">
        <Link href={`/reports/${encodeURIComponent(result.report_id)}`} className="text-primary underline">
          View asset report
        </Link>
        <Link href="/vulnerabilities" className="text-primary underline">
          Findings
        </Link>
      </div>
    );
  }
  if (result.kind === "flow" && result.batch_id) {
    return (
      <div className="text-sm">
        <span className="text-muted-foreground">batch </span>
        <span className="font-mono">{result.batch_id}</span> —{" "}
        <Link href="/flows" className="text-primary underline">
          View flows
        </Link>
      </div>
    );
  }
  if (result.kind === "guard") {
    return (
      <div className="flex flex-col gap-1 text-sm">
        {result.detail && <span className="text-muted-foreground">{result.detail}</span>}
        <Link
          href={`/guard?host=${encodeURIComponent(result.host_id ?? "")}`}
          className="text-primary underline"
        >
          View guard events
        </Link>
      </div>
    );
  }
  return null;
}
