/**
 * Sidebar navigation model. Grouped so the scan workflow (配置 → 下发 → 结果)
 * reads top-to-bottom, with correlation/prediction views below it.
 */

import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Bug,
  GitBranch,
  LayoutDashboard,
  Network,
  Radar,
  ScanLine,
  Server,
  ShieldAlert,
  Target,
} from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Marks the primary call-to-action item in the sidebar. */
  emphasis?: boolean;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: "总览",
    items: [{ href: "/", label: "概览", icon: LayoutDashboard }],
  },
  {
    label: "扫描中心",
    items: [
      { href: "/targets", label: "扫描目标", icon: Target },
      { href: "/scans", label: "任务配置与下发", icon: ScanLine, emphasis: true },
    ],
  },
  {
    label: "扫描结果",
    items: [
      { href: "/reports", label: "资产报告", icon: Server },
      { href: "/vulnerabilities", label: "漏洞发现", icon: Bug },
      { href: "/traces", label: "网络追踪", icon: Network },
      { href: "/guard", label: "防护事件", icon: ShieldAlert },
    ],
  },
  {
    label: "关联与预测",
    items: [
      { href: "/alerts", label: "关联告警", icon: Activity },
      { href: "/attack-paths", label: "攻击路径", icon: GitBranch },
    ],
  },
];

export const BRAND = { name: "Kcatta", tagline: "安全态势平台", icon: Radar };

/**
 * Pick the nav item that owns a pathname (longest matching href wins so
 * `/scans/abc` highlights `/scans`, not `/`).
 */
export function activeHref(pathname: string): string {
  const all = NAV.flatMap((g) => g.items.map((i) => i.href));
  const matches = all
    .filter((href) => (href === "/" ? pathname === "/" : pathname.startsWith(href)))
    .sort((a, b) => b.length - a.length);
  return matches[0] ?? "/";
}
