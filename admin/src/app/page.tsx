import { Activity, Bug, ChevronRight, Server, ScanLine, Target as TargetIcon } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/page-header";
import { SectionHeading } from "@/components/section-heading";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanJobsTable } from "@/components/scan-jobs-table";
import { Stat } from "@/components/stat";
import { EmptyState, ErrorState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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

  // Every fetch failing usually means analyzer is unreachable — show one error state.
  if (
    [targetsR, jobsR, reportsR, vulnsR, alertsR].every((r) => r.status === "rejected")
  ) {
    const reason = targetsR.status === "rejected" ? targetsR.reason : undefined;
    const message =
      reason instanceof Error ? reason.message : "无法连接 analyzer API，请确认服务可达。";
    return (
      <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
        <PageHeader eyebrow="蓝队 · 总览" title="防守概览" description="安全态势平台总览。" />
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
  const sevMax = Math.max(1, ...SEVERITY_ORDER.map((s) => severityCounts[s]));

  const recentReports = reports.slice(0, 6);

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        eyebrow="蓝队 · 总览 · INTELLIGENCE BRIEF"
        title="防守概览"
        description="一站式查看扫描目标、任务进度、资产报告与漏洞发现，掌握当前防守态势。"
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

      <div className="flex flex-col gap-9">
        {/* 01 — key indicators */}
        <section>
          <SectionHeading index="01" title="关键指标" />
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              label="扫描目标"
              value={targets.length}
              icon={TargetIcon}
              swatch="var(--team-blue)"
              sublabel="纳管资产范围"
            />
            <Stat
              label="扫描任务"
              value={jobs.length}
              icon={ScanLine}
              swatch="var(--team-blue)"
              delta={runningJobs > 0 ? `● ${runningJobs}` : undefined}
              sublabel={`执行中 ${runningJobs}`}
            />
            <Stat
              label="资产报告"
              value={reports.length}
              icon={Server}
              swatch="var(--team-blue)"
              sublabel="主机清单快照"
            />
            <Stat
              label="漏洞发现"
              value={vulnTotal}
              icon={Bug}
              accent="text-sev-high"
              swatch="var(--sev-high)"
              sublabel={`严重 ${severityCounts.critical} · 高危 ${severityCounts.high}`}
            />
          </div>
        </section>

        {/* 02 — severity distribution + key alerts */}
        <section>
          <SectionHeading index="02" title="态势速览" />
          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardContent className="flex flex-col gap-3.5">
                <span className="lp-eyebrow" data-tick>
                  漏洞严重度分布
                </span>
                {hasSeverity ? (
                  <ul className="flex flex-col gap-2.5">
                    {SEVERITY_ORDER.filter((s) => severityCounts[s] > 0).map((s) => (
                      <li key={s} className="flex items-center gap-3">
                        <span className="w-16 shrink-0">
                          <SeverityBadge severity={s} />
                        </span>
                        <span className="bg-rule-soft h-[6px] flex-1 overflow-hidden rounded-full">
                          <span
                            className="block h-full rounded-full"
                            style={{
                              width: `${(severityCounts[s] / sevMax) * 100}%`,
                              background: `var(--sev-${s === "info" ? "low" : s})`,
                            }}
                          />
                        </span>
                        <span className="lp-mono text-foreground w-8 shrink-0 text-right text-xs tabular-nums">
                          {severityCounts[s]}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-muted-foreground text-sm">暂无漏洞发现。</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardContent className="flex flex-col gap-3.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="lp-eyebrow" data-tick>
                    <Activity className="size-3.5" />
                    重点告警
                  </span>
                  {alerts.length > 0 && (
                    <Button variant="ghost" size="xs" render={<Link href="/alerts" />}>
                      全部告警
                    </Button>
                  )}
                </div>
                {topAlerts.length === 0 ? (
                  <p className="text-muted-foreground text-sm">暂无关联告警。</p>
                ) : (
                  <ul className="flex flex-col">
                    {topAlerts.map((alert) => (
                      <li key={alert.alert_id}>
                        <Link
                          href={`/alerts/${encodeURIComponent(alert.alert_id)}`}
                          className="hover:bg-muted/40 -mx-2 flex items-center gap-2.5 rounded-md px-2 py-1.5 transition-colors"
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
        </section>

        {/* 03 — recent scan jobs */}
        <section>
          <SectionHeading
            index="03"
            title="最近任务"
            trailing={
              jobs.length > 0 ? (
                <Button variant="ghost" size="xs" render={<Link href="/scans" />}>
                  全部任务
                </Button>
              ) : undefined
            }
          />
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

        {/* 04 — recent asset reports */}
        {recentReports.length > 0 && (
          <section>
            <SectionHeading
              index="04"
              title="最近资产报告"
              trailing={
                <Button variant="ghost" size="xs" render={<Link href="/reports" />}>
                  全部报告
                </Button>
              }
            />
            <div className="border-rule overflow-hidden rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>主机</TableHead>
                    <TableHead>系统</TableHead>
                    <TableHead className="hidden sm:table-cell">采集时间</TableHead>
                    <TableHead className="text-right">资产</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentReports.map((report) => {
                    const assetCount = (report.assets ?? []).length;
                    return (
                      <TableRow key={report.report_id} className="group">
                        <TableCell>
                          <Link
                            href={`/reports/${encodeURIComponent(report.report_id)}`}
                            className="text-foreground hover:text-brand font-mono text-sm font-medium transition-colors"
                          >
                            {report.host.hostname}
                          </Link>
                        </TableCell>
                        <TableCell className="text-muted-foreground font-mono text-xs">
                          {report.host.os}
                        </TableCell>
                        <TableCell className="text-muted-foreground hidden font-mono text-xs sm:table-cell">
                          {fmtTimestamp(report.collected_at)}
                        </TableCell>
                        <TableCell className="text-right">
                          <Badge variant="outline">{assetCount} 项</Badge>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
