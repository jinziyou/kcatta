import { Activity, CircleCheck, CircleX, ScanLine, Target as TargetIcon } from "lucide-react";
import Link from "next/link";

import { ScanConfigForm } from "@/components/scan-config-form";
import { ScanJobsTable } from "@/components/scan-jobs-table";
import { Stat } from "@/components/stat";
import { EmptyState, ErrorState } from "@/components/states";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalyzerApiError, listScans, listTargets } from "@/lib/api";
import type { ScanJob, ScanTarget } from "@/lib/contracts";

export const dynamic = "force-dynamic";

export default async function ScansPage() {
  let targets: ScanTarget[] = [];
  let jobs: ScanJob[] = [];
  let error: AnalyzerApiError | null = null;
  try {
    [targets, jobs] = await Promise.all([listTargets(), listScans()]);
  } catch (err) {
    error =
      err instanceof AnalyzerApiError
        ? err
        : new AnalyzerApiError(err instanceof Error ? err.message : String(err));
  }

  const running = jobs.filter((j) => j.state === "pending" || j.state === "running").length;
  const succeeded = jobs.filter((j) => j.state === "succeeded").length;
  const failed = jobs.filter((j) => j.state === "failed").length;

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="任务配置与下发"
        description="选择目标与扫描能力、配置参数后下发；analyzer 会远程部署 agent、采集并入库，结果可在下方任务列表追踪。"
        actions={
          <Button variant="outline" render={<Link href="/targets" />}>
            <TargetIcon />
            管理目标
          </Button>
        }
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : (
        <div className="flex flex-col gap-8">
          {/* KPI 概览条 */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat icon={ScanLine} label="扫描任务" value={jobs.length} sublabel="条记录" />
            <Stat icon={Activity} label="运行中" value={running} sublabel="pending + running" />
            <Stat icon={CircleCheck} label="成功" value={succeeded} accent="text-emerald-600" sublabel="succeeded" />
            <Stat icon={CircleX} label="失败" value={failed} accent="text-red-600" sublabel="failed" />
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">配置扫描任务</CardTitle>
            </CardHeader>
            <CardContent>
              {targets.length === 0 ? (
                <EmptyState
                  icon={TargetIcon}
                  title="尚未注册扫描目标"
                  description="需要先添加一台 analyzer 可达的主机，才能下发扫描任务。"
                >
                  <Button render={<Link href="/targets" />}>
                    <TargetIcon />
                    注册目标
                  </Button>
                </EmptyState>
              ) : (
                <ScanConfigForm targets={targets} />
              )}
            </CardContent>
          </Card>

          <section className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">扫描任务</h2>
              <span className="text-muted-foreground text-xs">{jobs.length} 条记录</span>
            </div>
            {jobs.length === 0 ? (
              <EmptyState
                icon={ScanLine}
                title="还没有扫描任务"
                description="配置并下发第一个扫描任务后，记录会出现在这里。"
              />
            ) : (
              <ScanJobsTable jobs={jobs} />
            )}
          </section>
        </div>
      )}
    </div>
  );
}
