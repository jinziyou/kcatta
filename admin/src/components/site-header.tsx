"use client";

import { usePathname } from "next/navigation";

import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { ThemeToggle } from "@/components/theme-toggle";
import { activeHref, NAV } from "@/lib/nav";

function current(pathname: string): { group: string; label: string } {
  const href = activeHref(pathname);
  for (const group of NAV) {
    const item = group.items.find((i) => i.href === href);
    if (item) return { group: group.label, label: item.label };
  }
  return { group: "总览", label: "Kcatta 蓝队防守台" };
}

/** Sticky top bar: sidebar toggle, current-section eyebrow + title, theme switch. */
export function SiteHeader() {
  const pathname = usePathname();
  const { group, label } = current(pathname);
  return (
    <header className="bg-background/80 border-rule sticky top-0 z-10 flex h-14 shrink-0 items-center gap-3 border-b px-4 backdrop-blur-sm">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="data-[orientation=vertical]:h-4" />
      <span className="lp-eyebrow hidden sm:inline-flex" data-tick>
        {group}
      </span>
      <span className="text-foreground text-sm font-semibold">{label}</span>
      <div className="ml-auto flex items-center gap-1">
        <ThemeToggle />
      </div>
    </header>
  );
}
