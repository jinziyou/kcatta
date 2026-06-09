import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { TriggerScanForm } from "@/components/trigger-scan-form";
import { FusionApiError, listScans, listTargets } from "@/lib/api";
import type { ScanJob, ScanJobState, ScanTarget } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const STATE_VARIANT: Record<ScanJobState, "outline" | "secondary" | "default" | "destructive"> = {
  pending: "outline",
  running: "secondary",
  succeeded: "default",
  failed: "destructive",
};

function fmt(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function JobCard({ job }: { job: ScanJob }) {
  return (
    <Link href={`/scans/${encodeURIComponent(job.job_id)}`}>
      <Card size="sm" className="transition-colors hover:bg-muted/30">
        <CardHeader>
          <CardTitle className="flex items-center justify-between gap-3">
            <span className="text-sm">
              <Badge variant="secondary">{job.capability}</Badge>{" "}
              <span className="text-muted-foreground font-mono">{job.address}</span>
            </span>
            <Badge variant={STATE_VARIANT[job.state]}>{job.state}</Badge>
          </CardTitle>
          <CardDescription className="flex flex-col gap-0.5 font-mono text-xs">
            <span className="text-muted-foreground/80 truncate">{job.job_id}</span>
            <span>created {fmt(job.created_at)}</span>
            {job.error && <span className="text-destructive">{job.error}</span>}
          </CardDescription>
        </CardHeader>
      </Card>
    </Link>
  );
}

export default async function ScansPage() {
  let targets: ScanTarget[] = [];
  let jobs: ScanJob[] = [];
  let error: FusionApiError | null = null;
  try {
    [targets, jobs] = await Promise.all([listTargets(), listScans()]);
  } catch (err) {
    error =
      err instanceof FusionApiError
        ? err
        : new FusionApiError(err instanceof Error ? err.message : String(err));
  }

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <header className="mb-8 flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Scans</h1>
        <p className="text-muted-foreground text-sm">
          Trigger host / flow / guard against a registered target; fusion deploys the agent and
          ingests the results.
        </p>
      </header>

      {error ? (
        <Card className="border-destructive/40">
          <CardHeader>
            <CardTitle className="text-destructive">Cannot reach fusion API</CardTitle>
            <CardDescription>{error.message}</CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <div className="flex flex-col gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Trigger a scan</CardTitle>
            </CardHeader>
            <CardContent>
              <TriggerScanForm targets={targets} />
            </CardContent>
          </Card>

          {jobs.length === 0 ? (
            <p className="text-muted-foreground text-sm">No scans triggered yet.</p>
          ) : (
            <div className="grid gap-3">
              {jobs.map((job) => (
                <JobCard key={job.job_id} job={job} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
