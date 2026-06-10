import { Activity, Bug, ChevronRight, Server, ScanLine, Target as TargetIcon } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanJobsTable } from "@/components/scan-jobs-table";
import { Stat } from "@/components/stat";
import { EmptyState, ErrorState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  listAlerts,
  listAssetReports,
  listScans,
  listTargets,
  listVulnerabilities,
} from "@/lib/api";
import type {
  Alert,
  AssetReport,
  DetectionResult,
  ScanJob,
  ScanTarget,
  Severity,
} from "@/lib/contracts";
import { fmtTimestamp } from "@/lib/format";
import { SEVERITY_ORDER, SEVERITY_RANK } from "@/lib/meta";

export const dynamic = "force-dynamic";

/** Unwrap a settled promise, returning `fallback` (and remembering failure) on rejection. */
function settled<T>(
  result: PromiseSettledResult<T>,
  fallback: T,
): { value: T; ok: boolean } {
  return result.status === "fulfilled"
    ? { value: result.value, ok: true }
    : { value: fallback, ok: false };
}

export default async function OverviewPage() {
  const [targetsR, jobsR, reportsR, vulnsR, alertsR] = await Promise.allSettled([
    listTargets(),
    listScans(),
    listAssetReports(20),
    listVulnerabilities(50),
    listAlerts(20),
  ]);

  // Every fetch failing usually means fusion is unreachable — show one error state.
  if (
    [targetsR, jobsR, reportsR, vulnsR, alertsR].every((r) => r.status === "rejected")
  ) {
    const reason = targetsR.status === "rejected" ? targetsR.reason : undefined;
    const message =
      reason instanceof Error ? reason.message : "无法连接 fusion API，请确认服务可达。";
    return (
      <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
        <PageHeader title="概览" description="安全态势平台总览。" />
        <ErrorState message={message} />
      </div>
    );
  }

  const targets = settled<ScanTarget[]>(targetsR, []).value;
  const jobs = settled<ScanJob[]>(jobsR, []).value;
  const reports = settled<AssetReport[]>(reportsR, []).value;
  const detections = settled<DetectionResult[]>(vulnsR, []).value;
  const alerts = settled<Alert[]>(alertsR, []).value;

  const topAlerts = [...alerts]
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.score - a.score)
    .slice(0, 5);

  const runningJobs = jobs.filter((j) => j.state === "running").length;

  // Aggregate finding severities across the recent detection results.
  const severityCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let vulnTotal = 0;
  for (const det of detections) {
    for (const v of det.vulnerabilities ?? []) {
      severityCounts[v.severity] += 1;
      vulnTotal += 1;
    }
  }
  const hasSeverity = SEVERITY_ORDER.some((s) => severityCounts[s] > 0);

  const recentReports = reports.slice(0, 6);

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="概览"
        description="一站式查看扫描目标、任务进度、资产报告与漏洞发现，掌握当前安全态势。"
        actions={
          <>
            <Button render={<Link href="/scans" />}>
              <ScanLine />
              配置并下发扫描
            </Button>
            <Button variant="outline" render={<Link href="/targets" />}>
              <TargetIcon />
              注册目标
            </Button>
          </>
        }
      />

      <div className="flex flex-col gap-8">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Stat label="扫描目标" value={targets.length} icon={TargetIcon} />
          <Stat
            label="扫描任务"
            value={jobs.length}
            icon={ScanLine}
            sublabel={`执行中 ${runningJobs}`}
          />
          <Stat label="资产报告" value={reports.length} icon={Server} />
          <Stat
            label="漏洞发现"
            value={vulnTotal}
            icon={Bug}
            accent="text-destructive"
            sublabel={`严重 ${severityCounts.critical} · 高危 ${severityCounts.high}`}
          />
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">漏洞分布</CardTitle>
            </CardHeader>
            <CardContent>
              {hasSeverity ? (
                <div className="flex flex-wrap gap-2">
                  {SEVERITY_ORDER.filter((s) => severityCounts[s] > 0).map((s) => (
                    <SeverityBadge key={s} severity={s} count={severityCounts[s]} />
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground text-sm">暂无漏洞发现。</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Activity className="text-muted-foreground size-4" />
                重点告警
              </CardTitle>
              {alerts.length > 0 && (
                <CardAction>
                  <Button variant="ghost" size="xs" render={<Link href="/alerts" />}>
                    全部告警
                  </Button>
                </CardAction>
              )}
            </CardHeader>
            <CardContent>
              {topAlerts.length === 0 ? (
                <p className="text-muted-foreground text-sm">暂无关联告警。</p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {topAlerts.map((alert) => (
                    <li key={alert.alert_id}>
                      <Link
                        href={`/alerts/${encodeURIComponent(alert.alert_id)}`}
                        className="hover:bg-muted/40 -mx-2 flex items-center gap-2 rounded-md px-2 py-1 transition-colors"
                      >
                        <SeverityBadge severity={alert.severity} />
                        <span className="truncate text-sm">{alert.title}</span>
                        <span className="text-muted-foreground ml-auto flex items-center gap-1 font-mono text-xs tabular-nums">
                          {alert.score.toFixed(0)}
                          <ChevronRight className="size-3.5" />
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <section className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">最近任务</h2>
            {jobs.length > 0 && (
              <Button variant="ghost" size="xs" render={<Link href="/scans" />}>
                全部任务
              </Button>
            )}
          </div>
          {jobs.length === 0 ? (
            <EmptyState
              icon={ScanLine}
              title="还没有扫描任务"
              description="配置并下发第一个扫描任务后，记录会出现在这里。"
            >
              <Button render={<Link href="/scans" />}>
                <ScanLine />
                配置并下发扫描
              </Button>
            </EmptyState>
          ) : (
            <ScanJobsTable jobs={jobs.slice(0, 6)} />
          )}
        </section>

        {recentReports.length > 0 && (
          <section className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">最近资产报告</h2>
              <Button variant="ghost" size="xs" render={<Link href="/reports" />}>
                全部报告
              </Button>
            </div>
            <div className="overflow-hidden rounded-xl border">
              <ul className="divide-y">
                {recentReports.map((report) => {
                  const assetCount = (report.assets ?? []).length;
                  return (
                    <li key={report.report_id}>
                      <Link
                        href={`/reports/${encodeURIComponent(report.report_id)}`}
                        className="hover:bg-muted/30 flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 transition-colors"
                      >
                        <span className="truncate font-mono text-sm font-medium">
                          {report.host.hostname}
                        </span>
                        <Badge variant="secondary">{report.host.os}</Badge>
                        <span className="text-muted-foreground ml-auto font-mono text-xs">
                          {fmtTimestamp(report.collected_at)}
                        </span>
                        <Badge variant="outline">{assetCount} 项资产</Badge>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
