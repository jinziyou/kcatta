import { ChevronRight } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { CopyableId } from "@/components/copy-button";
import { ScanJobMonitor } from "@/components/scan-job-monitor";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FormApiError, getScan } from "@/lib/api";
import type { ScanJob } from "@/lib/contracts";
import { CAPABILITY_META } from "@/lib/meta";

export const dynamic = "force-dynamic";

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
    if (err instanceof FormApiError && err.status === 404) notFound();
    throw err;
  }
  if (!job) notFound();

  const meta = CAPABILITY_META[job.capability];

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-8">
      <nav className="text-muted-foreground mb-5 flex items-center gap-1 text-sm">
        <Link href="/scans" className="hover:text-foreground">
          任务配置与下发
        </Link>
        <ChevronRight className="size-3.5" />
        <span className="text-foreground">任务详情</span>
      </nav>

      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-base">
            <Badge variant="secondary">{meta.label}</Badge>
            <span className="text-muted-foreground font-mono text-sm">{job.address}</span>
          </CardTitle>
          <div className="text-muted-foreground flex items-center gap-1 text-xs">
            <span>任务</span>
            <CopyableId value={job.job_id} />
          </div>
        </CardHeader>
        <CardContent>
          <ScanJobMonitor initial={job} />
        </CardContent>
      </Card>
    </div>
  );
}
