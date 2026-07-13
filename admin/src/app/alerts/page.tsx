import { Activity, ChevronRight, Inbox, ShieldAlert, TriangleAlert } from "lucide-react";
import Link from "next/link";

import { AlertStatusBadge } from "@/components/alert-status-badge";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Stat } from "@/components/stat";
import { RevealRows } from "@/components/reveal";
import { EmptyState, ErrorState } from "@/components/states";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FormApiError, listAlerts } from "@/lib/api";
import type { Alert, Severity } from "@/lib/contracts";
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
  let error: FormApiError | null = null;
  try {
    alerts = await listAlerts(50);
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  const sorted = [...alerts].sort(bySeverity);

  const sevCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const a of alerts) sevCounts[a.severity] += 1;
  const openCount = alerts.filter((a) => (a.status ?? "open") === "open").length;

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="关联告警"
        description="分析引擎将资产、漏洞与流量证据关联生成安全告警，由 Form 统一提供，按严重度与风险分排序。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : alerts.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="暂无关联告警"
          description="当采集到的资产 / 漏洞 / 流量命中威胁规则并完成关联后，告警会出现在这里。"
        />
      ) : (
        <div className="flex flex-col gap-6">
          {/* KPI 概览条 */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat icon={Activity} label="告警总数" value={alerts.length} sublabel="近 50 条" />
            <Stat
              icon={ShieldAlert}
              label="严重"
              value={sevCounts.critical}
              accent="text-red-600"
              sublabel="critical"
            />
            <Stat
              icon={TriangleAlert}
              label="高危"
              value={sevCounts.high}
              accent="text-orange-500"
              sublabel="high"
            />
            <Stat icon={Inbox} label="待处理" value={openCount} sublabel="open 状态" />
          </div>

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
              <RevealRows colSpan={6} initial={15} step={15}>
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
                    {(alert.occurrence_count ?? 1) > 1 && (
                      <span className="text-muted-foreground ml-2 text-xs tabular-nums">
                        ×{alert.occurrence_count}
                      </span>
                    )}
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
              </RevealRows>
            </TableBody>
          </Table>
          </div>
        </div>
      )}
    </div>
  );
}
