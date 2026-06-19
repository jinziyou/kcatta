/**
 * Domain label + presentation metadata (Chinese-localized).
 *
 * Maps the wire enums (scan capability / job state / finding severity) to the
 * labels, descriptions, and badge styling the UI renders. Centralized so every
 * page agrees on how a `high` severity or a `running` job looks.
 */

import type { AlertStatus, ScanCapability, ScanJobState, ScanMode, Severity } from "./contracts";

// ---- execution mode (单次 / 常驻) ------------------------------------------

export interface ModeMeta {
  value: ScanMode;
  label: string;
  short: string;
  description: string;
}

export const MODE_META: Record<ScanMode, ModeMeta> = {
  oneshot: {
    value: "oneshot",
    label: "单次检测",
    short: "单次",
    description: "运行一次、产出快照即结束（主机扫描 / 流量采集）。",
  },
  resident: {
    value: "resident",
    label: "常驻代理",
    short: "常驻",
    description: "在目标上启动常驻守护进程，持续检测并回传事件（实时防护）。",
  },
};

export const MODE_ORDER: ScanMode[] = ["oneshot", "resident"];

/** Which capabilities each execution mode offers. */
export const MODE_CAPABILITIES: Record<ScanMode, ScanCapability[]> = {
  oneshot: ["host", "trace"],
  resident: ["guard"],
};

/** The execution mode a capability runs in (guard = resident, else oneshot). */
export function capabilityMode(capability: ScanCapability): ScanMode {
  return capability === "guard" ? "resident" : "oneshot";
}

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
  running: { label: "执行中", variant: "outline", dot: "bg-brand", terminal: false },
  succeeded: { label: "成功", variant: "outline", dot: "bg-ok", terminal: true },
  failed: { label: "失败", variant: "outline", dot: "bg-destructive", terminal: true },
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
  /**
   * Archive-palette dot+text classes for the {@link SeverityBadge}. No solid
   * high-saturation fills — a small colored dot plus matching mono text in the
   * `--sev-*` hue keeps it editorial.
   */
  text: string;
  /** background color class for the leading dot (sev hue) */
  dot: string;
  /**
   * Active-filter-chip styling: a low-tint sev fill so the selected chip reads
   * without a high-saturation block (used as `activeClassName`).
   */
  badge: string;
}

export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  critical: {
    label: "严重",
    text: "text-sev-critical",
    dot: "bg-sev-critical",
    badge: "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
  },
  high: {
    label: "高危",
    text: "text-sev-high",
    dot: "bg-sev-high",
    badge: "bg-sev-high/10 text-sev-high border-sev-high/30",
  },
  medium: {
    label: "中危",
    text: "text-sev-medium",
    dot: "bg-sev-medium",
    badge: "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
  },
  low: {
    label: "低危",
    text: "text-sev-low",
    dot: "bg-sev-low",
    badge: "bg-sev-low/15 text-sev-low border-sev-low/30",
  },
  info: {
    label: "提示",
    text: "text-muted-foreground",
    dot: "bg-muted-foreground",
    badge: "bg-muted text-muted-foreground border-border",
  },
};

export function severityRank(s: Severity): number {
  return SEVERITY_RANK[s] ?? 0;
}

// ---- alert status ------------------------------------------------------------

export interface AlertStatusMeta {
  label: string;
  variant: BadgeVariant;
  /**
   * Archive dossier dot color for the {@link AlertStatusBadge}: open →
   * destructive, acknowledged → medium sev, closed → warm low.
   */
  text: string;
  dot: string;
}

export const ALERT_STATUS_META: Record<AlertStatus, AlertStatusMeta> = {
  open: { label: "待处理", variant: "outline", text: "text-sev-critical", dot: "bg-sev-critical" },
  acknowledged: {
    label: "已确认",
    variant: "outline",
    text: "text-sev-medium",
    dot: "bg-sev-medium",
  },
  closed: { label: "已关闭", variant: "outline", text: "text-sev-low", dot: "bg-sev-low" },
};
