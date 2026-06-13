import { Activity, ChevronRight } from "lucide-react";
import Link from "next/link";

import { AlertStatusBadge } from "@/components/alert-status-badge";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState, ErrorState } from "@/components/states";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AnalyzerApiError, listAlerts } from "@/lib/api";
import type { Alert } from "@/lib/contracts";
import { fmtTimestamp } from "@/lib/format";
import { SEVERITY_RANK } from "@/lib/meta";

export const dynamic = "force-dynamic";

/** Most severe + highest risk first, so the worst alerts surface at the top. */
function bySeverity(a: Alert, b: Alert): number {
  const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (rank !== 0) return rank;
  return b.score - a.score;
}

export default async function AlertsPage() {
  let alerts: Alert[] = [];
  let error: AnalyzerApiError | null = null;
  try {
    alerts = await listAlerts(50);
  } catch (err) {
    error =
      err instanceof AnalyzerApiError
        ? err
        : new AnalyzerApiError(err instanceof Error ? err.message : String(err));
  }

  const sorted = [...alerts].sort(bySeverity);

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="关联告警"
        description="analyzer 将资产、漏洞与流量证据关联生成的安全告警，按严重度与风险分排序，最新在库。"
        actions={
          alerts.length > 0 ? (
            <span className="text-muted-foreground text-xs">{alerts.length} 条告警</span>
          ) : undefined
        }
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : alerts.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="暂无关联告警"
          description="当采集到的资产 / 漏洞 / 流量命中威胁规则并被 analyzer 关联后，告警会出现在这里。"
        />
      ) : (
        <div className="overflow-hidden rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/40 hover:bg-muted/40">
                <TableHead className="w-20">严重度</TableHead>
                <TableHead className="hidden w-20 sm:table-cell">风险分</TableHead>
                <TableHead>标题</TableHead>
                <TableHead className="w-24">状态</TableHead>
                <TableHead className="hidden w-44 md:table-cell">创建时间</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted.map((alert) => (
                <TableRow key={alert.alert_id} className="group">
                  <TableCell>
                    <SeverityBadge severity={alert.severity} />
                  </TableCell>
                  <TableCell className="hidden tabular-nums sm:table-cell">
                    {alert.score.toFixed(0)}
                  </TableCell>
                  <TableCell className="max-w-md">
                    <Link
                      href={`/alerts/${encodeURIComponent(alert.alert_id)}`}
                      className="line-clamp-2 font-medium hover:underline"
                    >
                      {alert.title}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <AlertStatusBadge status={alert.status ?? "open"} />
                  </TableCell>
                  <TableCell className="text-muted-foreground hidden font-mono text-xs md:table-cell">
                    {fmtTimestamp(alert.created_at)}
                  </TableCell>
                  <TableCell>
                    <Link
                      href={`/alerts/${encodeURIComponent(alert.alert_id)}`}
                      aria-label="查看告警详情"
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
      )}
    </div>
  );
}
