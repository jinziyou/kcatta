/**
 * Domain label + presentation metadata (Chinese-localized).
 *
 * Maps the wire enums (scan capability / job state / finding severity) to the
 * labels, descriptions, and badge styling the UI renders. Centralized so every
 * page agrees on how a `high` severity or a `running` job looks.
 */

import type { AlertStatus, ScanCapability, ScanJobState, Severity } from "./contracts";

// ---- scan capability -------------------------------------------------------

export interface CapabilityMeta {
  value: ScanCapability;
  label: string;
  short: string;
  description: string;
  /** Resulting artifact, shown on result panels. */
  produces: string;
}

export const CAPABILITY_META: Record<ScanCapability, CapabilityMeta> = {
  host: {
    value: "host",
    label: "主机扫描",
    short: "Host",
    description: "采集主机资产清单（包 / 服务 / 端口 / 账号 / 凭据）并执行静态恶意文件检测。",
    produces: "资产报告",
  },
  trace: {
    value: "trace",
    label: "流量采集",
    short: "Trace",
    description: "在目标上抓取一段网络流量，提取会话特征并做 IOC 初筛。",
    produces: "流量批次",
  },
  guard: {
    value: "guard",
    label: "实时防护",
    short: "Guard",
    description: "在目标上启动常驻守护进程，持续监控文件 / 进程 / 网络并回传事件。",
    produces: "防护事件流",
  },
};

export const CAPABILITY_ORDER: ScanCapability[] = ["host", "trace", "guard"];

// ---- scan job state --------------------------------------------------------

export type BadgeVariant = "outline" | "secondary" | "default" | "destructive";

export interface StateMeta {
  label: string;
  variant: BadgeVariant;
  /** dot/pulse color class for timelines. */
  dot: string;
  terminal: boolean;
}

export const STATE_META: Record<ScanJobState, StateMeta> = {
  pending: { label: "排队中", variant: "outline", dot: "bg-muted-foreground", terminal: false },
  running: { label: "执行中", variant: "secondary", dot: "bg-blue-500", terminal: false },
  succeeded: { label: "成功", variant: "default", dot: "bg-emerald-500", terminal: true },
  failed: { label: "失败", variant: "destructive", dot: "bg-destructive", terminal: true },
};

// ---- finding severity ------------------------------------------------------

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export interface SeverityMeta {
  label: string;
  /** solid badge classes */
  badge: string;
}

export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  critical: { label: "严重", badge: "bg-red-600 text-white border-transparent" },
  high: { label: "高危", badge: "bg-orange-500 text-white border-transparent" },
  medium: { label: "中危", badge: "bg-amber-400 text-black border-transparent" },
  low: { label: "低危", badge: "bg-slate-300 text-black border-transparent" },
  info: { label: "提示", badge: "bg-slate-200 text-black border-transparent" },
};

export function severityRank(s: Severity): number {
  return SEVERITY_RANK[s] ?? 0;
}

// ---- alert status ------------------------------------------------------------

export interface AlertStatusMeta {
  label: string;
  variant: BadgeVariant;
}

export const ALERT_STATUS_META: Record<AlertStatus, AlertStatusMeta> = {
  open: { label: "待处理", variant: "destructive" },
  acknowledged: { label: "已确认", variant: "secondary" },
  closed: { label: "已关闭", variant: "outline" },
};
