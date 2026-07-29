"use client";

import { Bug, FileText, Network, RefreshCw, RotateCcw, ServerCog, ShieldAlert, X } from "lucide-react";
import Link from "next/link";
import { useEffect, useState, useTransition } from "react";

import { cancelScanAction, pollScanAction, retryScanAction } from "@/app/scans/actions";
import { CopyableId } from "@/components/copy-button";
import { StateBadge } from "@/components/state-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import type { ScanJob } from "@/lib/contracts";
import { detectionReasonLabel } from "@/lib/detection";
import { fmtDuration, fmtRelative, fmtTimestampFull } from "@/lib/format";
import { STATE_META } from "@/lib/meta";
import { cn } from "@/lib/utils";

const POLL_MS = 2500;
const MAX_BACKOFF_MS = 30000;
const MAX_POLL_FAILURES = 6;

/** Live job view; continues polling until execution and Analyzer derivation are terminal. */
export function ScanJobMonitor({ initial }: { initial: ScanJob }) {
  const [job, setJob] = useState<ScanJob>(initial);
  const [stale, setStale] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionPending, startTransition] = useTransition();
  const terminal = STATE_META[job.state].terminal;
  const derivedActive =
    job.result?.derived_state === "pending" || job.result?.derived_state === "processing";
  const watching = !terminal || derivedActive;
  const canCancel = ["pending", "retrying", "running"].includes(job.state);
  const canRetry = job.state === "failed" || job.state === "cancelled";

  const runAction = (kind: "cancel" | "retry") => {
    setActionError(null);
    startTransition(async () => {
      const result =
        kind === "cancel"
          ? await cancelScanAction(job.job_id)
          : await retryScanAction(job.job_id);
      if (result.ok) setJob(result.job);
      else setActionError(result.error);
    });
  };

  useEffect(() => {
    if (!watching) return;
    // Self-scheduling poll: the next request is only queued AFTER the previous one
    // settles (no overlapping in-flight requests stacking up when Form is
    // slow), with exponential backoff on failure and a give-up cap so a persistent
    // outage doesn't hammer the backend at a fixed rate forever.
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    let failures = 0;

    const tick = async () => {
      const next = await pollScanAction(job.job_id);
      if (!active) return;
      if (next) {
        failures = 0;
        setStale(false);
        setJob(next);
        const nextDerivedActive =
          next.result?.derived_state === "pending" ||
          next.result?.derived_state === "processing";
        if (!STATE_META[next.state].terminal || nextDerivedActive) {
          timer = setTimeout(tick, POLL_MS);
        }
      } else {
        failures += 1;
        setStale(true);
        if (failures <= MAX_POLL_FAILURES) {
          const delay = Math.min(POLL_MS * 2 ** failures, MAX_BACKOFF_MS);
          timer = setTimeout(tick, delay);
        }
      }
    };

    timer = setTimeout(tick, POLL_MS);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [watching, job.job_id]);

  return (
    <div className="grid gap-6 lg:grid-cols-[1.1fr_1fr]">
      <div className="flex flex-col gap-5">
        <div className="flex items-center gap-2">
          <StateBadge state={job.state} />
          {watching &&
            (stale ? (
              <span className="text-destructive inline-flex items-center gap-1.5 text-xs">
                <RefreshCw className="size-3" />
                连接中断，正在重试…（可刷新页面）
              </span>
            ) : (
              <span className="text-muted-foreground inline-flex items-center gap-1.5 text-xs">
                <RefreshCw className="size-3 animate-spin" />
                {terminal ? "Analyzer 正在生成检测结果" : `每 ${POLL_MS / 1000}s 自动刷新`}
              </span>
            ))}
        </div>

        <div className="flex flex-wrap gap-2">
          {canCancel && (
            <Button
              size="sm"
              variant="outline"
              disabled={actionPending}
              onClick={() => runAction("cancel")}
            >
              <X />
              {actionPending ? "提交中…" : "取消任务"}
            </Button>
          )}
          {canRetry && (
            <Button size="sm" disabled={actionPending} onClick={() => runAction("retry")}>
              <RotateCcw />
              {actionPending ? "提交中…" : "重新排队"}
            </Button>
          )}
        </div>
        {actionError && <p className="text-destructive text-xs">{actionError}</p>}

        <Timeline job={job} />

        {job.state === "retrying" && job.available_at && (
          <p className="text-muted-foreground text-xs">
            下次尝试：{fmtTimestampFull(job.available_at)} · {fmtRelative(job.available_at)}
          </p>
        )}
        {job.error && job.state !== "cancelled" && (
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
      done:
        job.state === "running" ||
        job.state === "cancelling" ||
        STATE_META[job.state].terminal,
      active: job.state === "running" || job.state === "cancelling",
    },
    {
      label:
        job.state === "failed" ? "失败" : job.state === "cancelled" ? "已取消" : "完成",
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
      {job.attempt > 0 && (
        <li className="text-muted-foreground pl-0 text-xs">
          已执行 {job.attempt} / {job.max_attempts} 次
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
    <div className="rounded-lg border p-4">
      <h3 className="mb-1 text-sm font-semibold">下发参数</h3>
      <Separator className="mb-1" />
      {job.capability === "host" && (
        <>
          <Row label="扫描对象">{o.scan_target}</Row>
          <Row label="恶意文件检测">{o.malware ? "开启" : "关闭"}</Row>
          <Row label="安全基线检测">{o.posture === false ? "关闭" : "开启"}</Row>
          <Row label="密钥泄露检测">{o.secrets ? "开启" : "关闭"}</Row>
        </>
      )}
      {job.capability === "trace" && (
        <>
          <Row label="采集后端">{o.pcap ? "libpcap（自定义构建）" : "真实 OS 连接表"}</Row>
          <Row label="监听网卡">{o.iface}</Row>
          <Row label="抓包时长">{o.duration}s</Row>
          <Row label="BPF">{o.bpf}</Row>
          <Row label="IOC 威胁情报">{o.intel === false ? "关闭" : "开启"}</Row>
          <Row label="eBPF 文件/进程">{o.ebpf ? "开启" : "关闭"}</Row>
        </>
      )}
      {job.capability === "guard" && (
        <>
          <Row label="模式">常驻守护进程（持续回传）</Row>
          <Row label="网络 IOC / IDS">{o.guard_network === false ? "关闭" : "开启"}</Row>
          <Row label="文件打开时查毒">{o.guard_onaccess ? "开启" : "关闭"}</Row>
        </>
      )}
    </div>
  );
}

function ResultPanel({ job }: { job: ScanJob }) {
  const result = job.result;

  if (job.state === "failed" || job.state === "cancelled") {
    return (
      <div className="text-muted-foreground rounded-lg border border-dashed p-4 text-sm">
        {job.state === "cancelled"
          ? "任务已取消；执行采用至少一次语义，取消前已发生的远端或分析副作用可能无法撤销。"
          : "任务失败，未产生结果。请检查上方错误信息与目标连通性。"}
      </div>
    );
  }
  if (!result) {
    return (
      <div className="text-muted-foreground rounded-lg border border-dashed p-4 text-sm">
        {STATE_META[job.state].terminal ? "本次任务无可查看的结果产物。" : "任务执行中，结果产生后将在此显示。"}
      </div>
    );
  }

  return (
    <div className="bg-card rounded-lg border p-4">
      <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold">
        {result.kind === "host" && <ServerCog className="text-primary size-4" />}
        {result.kind === "trace" && <Network className="text-primary size-4" />}
        {result.kind === "guard" && <ShieldAlert className="text-primary size-4" />}
        扫描结果
        {result.derived_state && (
          <Badge
            variant={result.derived_state === "partial" ? "destructive" : "secondary"}
            className="ml-auto"
          >
            {result.derived_state === "pending" && "检测排队中"}
            {result.derived_state === "processing" && "检测处理中"}
            {result.derived_state === "complete" && "检测完成"}
            {result.derived_state === "partial" && "检测部分完成"}
          </Badge>
        )}
      </h3>

      {result.derived_state && (
        <div className="bg-muted/40 mb-3 rounded-md px-3 py-2 text-xs">
          <p>{result.detail ?? "Analyzer 派生状态已更新"}</p>
          <p className="text-muted-foreground mt-1">
            已生成 {result.derived_records} 条结果
            {result.derived_attempts > 0 ? ` · 尝试 ${result.derived_attempts} 次` : ""}
            {result.derived_truncated ? " · 已达到结果上限" : ""}
          </p>
          {result.derived_reason && (
            <p className="text-muted-foreground mt-1">
              原因：{detectionReasonLabel(result.derived_reason)}
            </p>
          )}
        </div>
      )}

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
            <Button
              size="sm"
              render={
                <Link href={`/traces?batch=${encodeURIComponent(result.batch_id)}`} />
              }
            >
              <Network />
              查看完整追踪结果
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
