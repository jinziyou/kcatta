import { Activity, ChevronRight, Inbox, ShieldAlert, TriangleAlert } from "lucide-react";
import Link from "next/link";

import { AlertStatusBadge } from "@/components/alert-status-badge";
import { FilterChip } from "@/components/filter-chip";
import { PageHeader } from "@/components/page-header";
import { PageNav } from "@/components/page-nav";
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
import { pageHref, parsePage, REPORT_PAGE_SIZE } from "@/lib/pagination";

export const dynamic = "force-dynamic";

/** Most severe + highest risk first, so the worst alerts surface at the top. */
function bySeverity(a: Alert, b: Alert): number {
  const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (rank !== 0) return rank;
  return b.score - a.score;
}

export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<{ suppressed?: string | string[]; page?: string | string[] }>;
}) {
  const params = await searchParams;
  const includeSuppressed = params.suppressed === "1" || params.suppressed === "true";
  const page = parsePage(params.page);
  let alerts: Alert[] = [];
  let hasNext = false;
  let error: FormApiError | null = null;
  try {
    const rows = await listAlerts(
      REPORT_PAGE_SIZE + 1,
      includeSuppressed,
      page * REPORT_PAGE_SIZE,
    );
    hasNext = rows.length > REPORT_PAGE_SIZE;
    alerts = rows.slice(0, REPORT_PAGE_SIZE);
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
  const suppressedCount = alerts.filter((alert) => alert.suppressed).length;
  const previousHref = page > 0
    ? pageHref("/alerts", page - 1, { suppressed: includeSuppressed ? "1" : null })
    : undefined;
  const nextHref = hasNext
    ? pageHref("/alerts", page + 1, { suppressed: includeSuppressed ? "1" : null })
    : undefined;

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="关联告警"
        description="分析引擎关联资产、漏洞与事件证据生成逻辑告警；可查看已抑制项并逐页翻阅历史。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : alerts.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="暂无关联告警"
          description={
            page > 0
              ? "这一页没有关联告警，请返回上一页。"
              : includeSuppressed
                ? "当前没有关联告警。"
                : "当前没有未抑制告警；可切换为包含已抑制项。"
          }
        >
          {page > 0 ? (
            <PageNav page={page} count={0} previousHref={previousHref} />
          ) : !includeSuppressed ? (
            <FilterChip href="/alerts?suppressed=1" label="包含已抑制" active={false} />
          ) : null}
        </EmptyState>
      ) : (
        <div className="flex flex-col gap-6">
          {/* KPI 概览条 */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat icon={Activity} label="告警总数" value={alerts.length} sublabel="本页逻辑告警" />
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
            <Stat
              icon={Inbox}
              label="待处理"
              value={openCount}
              sublabel={includeSuppressed ? `本页已抑制 ${suppressedCount}` : "open 状态"}
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground text-xs">显示范围</span>
            <FilterChip href="/alerts" label="隐藏已抑制" active={!includeSuppressed} />
            <FilterChip
              href="/alerts?suppressed=1"
              label="包含已抑制"
              active={includeSuppressed}
            />
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
                    {alert.suppressed && (
                      <span className="ml-2 text-xs text-muted-foreground">已抑制</span>
                    )}
                    {alert.evidence_truncated && (
                      <span className="ml-2 text-xs text-amber-700 dark:text-amber-400">
                        证据已截断
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

          <PageNav
            page={page}
            count={alerts.length}
            previousHref={previousHref}
            nextHref={nextHref}
          />
        </div>
      )}
    </div>
  );
}
