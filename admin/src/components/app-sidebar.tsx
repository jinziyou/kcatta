"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar";
import { activeHref, BRAND, NAV, SERVICES, type TeamColor } from "@/lib/nav";

/** Maps a classification color to its CSS custom property (light/dark aware). */
const TEAM_VAR: Record<TeamColor, string> = {
  purple: "var(--team-purple)",
  red: "var(--team-red)",
  blue: "var(--team-blue)",
  warm: "var(--muted-foreground)",
};

export function AppSidebar() {
  const pathname = usePathname();
  const active = activeHref(pathname);

  return (
    <Sidebar collapsible="icon">
      {/* ---- brand: loopsec serif + blue dot, three-color subtitle ---- */}
      <SidebarHeader className="border-sidebar-border gap-0 border-b px-3 py-4">
        <Link href="/" className="flex flex-col gap-2.5">
          <span className="font-heading text-foreground flex items-baseline gap-0.5 text-2xl leading-none font-semibold tracking-tight group-data-[collapsible=icon]:hidden">
            loopsec
            <span className="text-team-blue relative -top-[1px] text-[1.3em] leading-[0]">.</span>
          </span>
          <span className="lp-eyebrow gap-2 group-data-[collapsible=icon]:hidden">
            <span className="flex gap-1" aria-hidden>
              <span className="size-1.5 rounded-full" style={{ background: "var(--team-red)" }} />
              <span className="size-1.5 rounded-full" style={{ background: "var(--team-blue)" }} />
              <span
                className="size-1.5 rounded-full"
                style={{ background: "var(--team-purple)" }}
              />
            </span>
            红 · 蓝 · 紫 三色协同
          </span>
          {/* collapsed: show only the mark */}
          <span className="font-heading text-team-blue hidden text-2xl leading-none font-semibold group-data-[collapsible=icon]:block">
            l
          </span>
        </Link>
      </SidebarHeader>

      <SidebarContent>
        {NAV.map((group) => {
          const teamVar = TEAM_VAR[group.team ?? "blue"];
          return (
            <SidebarGroup key={group.label}>
              <SidebarGroupLabel className="lp-eyebrow text-muted-foreground h-7 gap-2 px-2">
                <span
                  className="size-[7px] shrink-0 rounded-[2px] shadow-[0_0_0_1px_color-mix(in_oklab,var(--foreground)_8%,transparent)]"
                  style={{ background: teamVar }}
                  aria-hidden
                />
                <span>{group.label}</span>
                <span className="lp-rule" aria-hidden />
              </SidebarGroupLabel>
              <SidebarMenu>
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = active === item.href;
                  return (
                    <SidebarMenuItem key={item.href}>
                      {/* active: 2px brand bar on the left edge */}
                      {isActive && (
                        <span
                          className="bg-brand absolute top-1.5 bottom-1.5 left-0 z-10 w-0.5 rounded-full group-data-[collapsible=icon]:hidden"
                          aria-hidden
                        />
                      )}
                      <SidebarMenuButton
                        isActive={isActive}
                        tooltip={item.label}
                        render={<Link href={item.href} />}
                      >
                        {/* leading team-color dot */}
                        <span
                          className="size-1.5 shrink-0 rounded-full transition-transform group-hover/menu-button:scale-150 group-data-[collapsible=icon]:hidden"
                          style={{ background: teamVar }}
                          aria-hidden
                        />
                        <Icon className="hidden group-data-[collapsible=icon]:block" />
                        <span className="font-medium">{item.label}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroup>
          );
        })}
      </SidebarContent>

      {/* ---- service health: 5 services with LED + mono port ---- */}
      <SidebarFooter className="border-sidebar-border border-t group-data-[collapsible=icon]:hidden">
        <div className="flex flex-col gap-2 px-1 py-1">
          <div className="lp-eyebrow gap-2 px-1">
            <span>服务健康</span>
            <span className="lp-rule" aria-hidden />
          </div>
          <ul className="flex flex-col gap-0.5">
            {SERVICES.map((svc) => (
              <li
                key={svc.name}
                className="lp-mono flex items-center gap-2 px-1 py-1 text-[0.6875rem]"
              >
                <span className="lp-led" aria-hidden />
                <span className="text-foreground font-medium">{svc.name}</span>
                <span className="text-muted-foreground ml-auto tabular-nums">{svc.port}</span>
              </li>
            ))}
          </ul>
        </div>
        <span className="sr-only">{BRAND.name} · 蓝队防守台</span>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
