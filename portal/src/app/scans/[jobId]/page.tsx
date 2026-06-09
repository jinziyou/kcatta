import Link from "next/link";
import { notFound } from "next/navigation";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ScanStatusPoller } from "@/components/scan-status-poller";
import { FusionApiError, getScan } from "@/lib/api";
import type { ScanJob } from "@/lib/contracts";

export const dynamic = "force-dynamic";

function fmt(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ jobId: string }>;
}) {
  const { jobId } = await params;

  let job: ScanJob | null = null;
  try {
    job = await getScan(jobId);
  } catch (err) {
    if (err instanceof FusionApiError && err.status === 404) notFound();
    throw err;
  }
  if (!job) notFound();

  return (
    <div className="mx-auto w-full max-w-3xl flex-1 p-6 sm:p-10">
      <Link
        href="/scans"
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm transition-colors"
      >
        ← Scans
      </Link>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{job.capability} scan</CardTitle>
          <CardDescription className="flex flex-col gap-0.5 font-mono text-xs">
            <span>job {job.job_id}</span>
            <span>target {job.address}</span>
            <span>created {fmt(job.created_at)}</span>
            {job.finished_at && <span>finished {fmt(job.finished_at)}</span>}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScanStatusPoller initial={job} />
        </CardContent>
      </Card>
    </div>
  );
}
