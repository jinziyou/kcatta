import { ChevronRight } from "lucide-react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { StateBadge } from "@/components/state-badge";
import type { ScanJob } from "@/lib/contracts";
import { fmtDuration, fmtTimestamp } from "@/lib/format";
import { CAPABILITY_META } from "@/lib/meta";

/** Sortable-by-recency table of scan jobs; each row links to the job detail. */
export function ScanJobsTable({ jobs }: { jobs: ScanJob[] }) {
  return (
    <div className="overflow-hidden rounded-xl border">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/40 hover:bg-muted/40">
            <TableHead>能力</TableHead>
            <TableHead>目标</TableHead>
            <TableHead>状态</TableHead>
            <TableHead className="hidden md:table-cell">创建时间</TableHead>
            <TableHead className="hidden sm:table-cell">耗时</TableHead>
            <TableHead className="w-10" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {jobs.map((job) => (
            <TableRow key={job.job_id} className="group">
              <TableCell>
                <Badge variant="secondary">{CAPABILITY_META[job.capability].label}</Badge>
              </TableCell>
              <TableCell className="font-mono text-xs">{job.address}</TableCell>
              <TableCell>
                <StateBadge state={job.state} />
                {job.error && (
                  <span className="text-destructive ml-2 line-clamp-1 text-xs">{job.error}</span>
                )}
              </TableCell>
              <TableCell className="text-muted-foreground hidden font-mono text-xs md:table-cell">
                {fmtTimestamp(job.created_at)}
              </TableCell>
              <TableCell className="text-muted-foreground hidden font-mono text-xs sm:table-cell">
                {fmtDuration(job.started_at, job.finished_at)}
              </TableCell>
              <TableCell>
                <Link
                  href={`/scans/${encodeURIComponent(job.job_id)}`}
                  aria-label="查看任务详情"
                  className="text-muted-foreground hover:text-foreground inline-flex"
                >
                  <ChevronRight className="size-4" />
                </Link>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
