/**
 * Sidebar navigation model. Grouped so the scan workflow (配置 → 下发 → 结果)
 * reads top-to-bottom, with correlation/prediction views below it.
 */

import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Bug,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  Network,
  ScanLine,
  Server,
  ShieldAlert,
  Target,
} from "lucide-react";
import { LoopsecMark } from "@/components/loopsec-mark";

/** Editorial team accent for a nav group's seal + each item's leading dot. */
export type TeamColor = "purple" | "red" | "blue" | "warm";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Marks the primary call-to-action item in the sidebar. */
  emphasis?: boolean;
}

export interface NavGroup {
  label: string;
  /** Classification color for the group seal + item dots (default blue). */
  team?: TeamColor;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: "总览",
    team: "blue",
    items: [{ href: "/", label: "概览", icon: LayoutDashboard }],
  },
  {
    label: "扫描中心",
    team: "blue",
    items: [
      { href: "/targets", label: "扫描目标", icon: Target },
      { href: "/credentials", label: "访问凭证", icon: KeyRound },
      { href: "/scans", label: "任务配置与下发", icon: ScanLine, emphasis: true },
    ],
  },
  {
    label: "扫描结果",
    team: "blue",
    items: [
      { href: "/reports", label: "资产报告", icon: Server },
      { href: "/vulnerabilities", label: "漏洞发现", icon: Bug },
      { href: "/traces", label: "网络追踪", icon: Network },
      { href: "/guard", label: "防护事件", icon: ShieldAlert },
    ],
  },
  {
    label: "关联与预测",
    team: "blue",
    items: [
      { href: "/alerts", label: "关联告警", icon: Activity },
      { href: "/attack-paths", label: "攻击路径", icon: GitBranch },
    ],
  },
];

export const BRAND = { name: "Kcatta", tagline: "蓝队防守台", icon: LoopsecMark };

/**
 * The five loopsec services shown in the sidebar health footer with their fixed
 * ports + classification team color (see design system §7). Static + always
 * "online" — purely a presence/identity affordance, not live telemetry.
 */
export interface ServiceHealth {
  name: string;
  port: string;
  team: Exclude<TeamColor, "warm">;
}

export const SERVICES: ServiceHealth[] = [
  { name: "analyzer", port: ":10068", team: "blue" },
  { name: "att7ck", port: ":10064", team: "red" },
  { name: "turn", port: ":10062", team: "purple" },
  { name: "admin", port: ":10063", team: "blue" },
  { name: "portal", port: ":10061", team: "purple" },
];

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
