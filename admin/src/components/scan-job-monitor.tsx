"use client";

import { Bug, FileText, Network, RefreshCw, ServerCog, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { pollScanAction } from "@/app/scans/actions";
import { CopyableId } from "@/components/copy-button";
import { StateBadge } from "@/components/state-badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import type { ScanJob } from "@/lib/contracts";
import { fmtDuration, fmtRelative, fmtTimestampFull } from "@/lib/format";
import { STATE_META } from "@/lib/meta";
import { cn } from "@/lib/utils";

const POLL_MS = 2500;

/** Live job view: timeline + dispatched options + result links; polls until terminal. */
export function ScanJobMonitor({ initial }: { initial: ScanJob }) {
  const [job, setJob] = useState<ScanJob>(initial);
  const terminal = STATE_META[job.state].terminal;

  useEffect(() => {
    if (terminal) return;
    const id = setInterval(async () => {
      const next = await pollScanAction(job.job_id);
      if (next) setJob(next);
    }, POLL_MS);
    return () => clearInterval(id);
  }, [terminal, job.job_id]);

  return (
    <div className="grid gap-6 lg:grid-cols-[1.1fr_1fr]">
      <div className="flex flex-col gap-5">
        <div className="flex items-center gap-2">
          <StateBadge state={job.state} />
          {!terminal && (
            <span className="text-muted-foreground inline-flex items-center gap-1.5 text-xs">
              <RefreshCw className="size-3 animate-spin" />
              每 {POLL_MS / 1000}s 自动刷新
            </span>
          )}
        </div>

        <Timeline job={job} />

        {job.error && (
          <pre className="bg-destructive/5 text-destructive overflow-x-auto rounded-lg border border-destructive/30 p-3 font-mono text-xs whitespace-pre-wrap">
            {job.error}
          </pre>
        )}
      </div>

      <div className="flex flex-col gap-5">
        <OptionsPanel job={job} />
        <ResultPanel job={job} />
      </div>
    </div>
  );
}

function Timeline({ job }: { job: ScanJob }) {
  const steps: { label: string; at: string | null; done: boolean; active?: boolean }[] = [
    { label: "已创建", at: job.created_at, done: true },
    {
      label: "执行中",
      at: job.started_at,
      done: job.state === "running" || STATE_META[job.state].terminal,
      active: job.state === "running",
    },
    {
      label: job.state === "failed" ? "失败" : "完成",
      at: job.finished_at,
      done: STATE_META[job.state].terminal,
    },
  ];

  return (
    <ol className="relative flex flex-col gap-5 pl-6">
      <span className="bg-border absolute top-1.5 bottom-1.5 left-[5px] w-px" />
      {steps.map((step) => (
        <li key={step.label} className="relative">
          <span
            className={cn(
              "absolute top-0.5 -left-6 size-2.5 rounded-full ring-4 ring-background",
              step.done ? "bg-primary" : "bg-muted-foreground/40",
              step.active && "animate-pulse",
            )}
          />
          <div className="flex flex-wrap items-baseline justify-between gap-x-3">
            <span className={cn("text-sm", step.done ? "font-medium" : "text-muted-foreground")}>
              {step.label}
            </span>
            {step.at && (
              <span className="text-muted-foreground font-mono text-xs">
                {fmtTimestampFull(step.at)} · {fmtRelative(step.at)}
              </span>
            )}
          </div>
        </li>
      ))}
      {STATE_META[job.state].terminal && (
        <li className="text-muted-foreground pl-0 text-xs">
          总耗时 {fmtDuration(job.started_at ?? job.created_at, job.finished_at)}
        </li>
      )}
    </ol>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right font-mono text-xs">{children}</span>
    </div>
  );
}

function OptionsPanel({ job }: { job: ScanJob }) {
  const o = job.options;
  return (
    <div className="rounded-xl border p-4">
      <h3 className="mb-1 text-sm font-semibold">下发参数</h3>
      <Separator className="mb-1" />
      {job.capability === "host" && (
        <>
          <Row label="扫描对象">{o.scan_target}</Row>
          <Row label="恶意文件检测">{o.malware ? "开启" : "关闭"}</Row>
        </>
      )}
      {job.capability === "trace" && (
        <>
          <Row label="实时抓包">{o.pcap ? "开启" : "模拟样本"}</Row>
          <Row label="监听网卡">{o.iface}</Row>
          <Row label="抓包时长">{o.duration}s</Row>
          <Row label="BPF">{o.bpf}</Row>
        </>
      )}
      {job.capability === "guard" && (
        <Row label="模式">常驻守护进程（持续回传）</Row>
      )}
    </div>
  );
}

function ResultPanel({ job }: { job: ScanJob }) {
  const result = job.result;

  if (job.state === "failed") {
    return (
      <div className="text-muted-foreground rounded-xl border border-dashed p-4 text-sm">
        任务失败，未产生结果。请检查上方错误信息与目标连通性。
      </div>
    );
  }
  if (!result) {
    return (
      <div className="text-muted-foreground rounded-xl border border-dashed p-4 text-sm">
        {STATE_META[job.state].terminal ? "本次任务无可查看的结果产物。" : "任务执行中，结果产生后将在此显示。"}
      </div>
    );
  }

  return (
    <div className="bg-card rounded-xl border p-4">
      <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold">
        {result.kind === "host" && <ServerCog className="text-primary size-4" />}
        {result.kind === "trace" && <Network className="text-primary size-4" />}
        {result.kind === "guard" && <ShieldAlert className="text-primary size-4" />}
        扫描结果
      </h3>

      {result.kind === "host" && result.report_id && (
        <div className="flex flex-col gap-3">
          <Row label="资产报告">
            <CopyableId value={result.report_id} />
          </Row>
          {result.host_id && (
            <Row label="主机">
              <CopyableId value={result.host_id} />
            </Row>
          )}
          <div className="flex flex-wrap gap-2 pt-1">
            <Button size="sm" render={<Link href={`/reports/${encodeURIComponent(result.report_id)}`} />}>
              <FileText />
              查看资产报告
            </Button>
            <Button size="sm" variant="outline" render={<Link href="/vulnerabilities" />}>
              <Bug />
              漏洞发现
            </Button>
          </div>
        </div>
      )}

      {result.kind === "trace" && result.batch_id && (
        <div className="flex flex-col gap-3">
          <Row label="流量批次">
            <CopyableId value={result.batch_id} />
          </Row>
          <div className="pt-1">
            <Button size="sm" render={<Link href="/traces" />}>
              <Network />
              查看网络流量
            </Button>
          </div>
        </div>
      )}

      {result.kind === "guard" && (
        <div className="flex flex-col gap-3">
          {result.detail && <p className="text-muted-foreground text-sm">{result.detail}</p>}
          {result.pid && <Row label="守护进程 PID">{result.pid}</Row>}
          {result.host_id && (
            <Row label="主机">
              <CopyableId value={result.host_id} />
            </Row>
          )}
          <div className="pt-1">
            <Button
              size="sm"
              render={<Link href={`/guard${result.host_id ? `?host=${encodeURIComponent(result.host_id)}` : ""}`} />}
            >
              <ShieldAlert />
              查看防护事件
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
