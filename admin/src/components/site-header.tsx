"use client";

import { usePathname } from "next/navigation";

import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { ThemeToggle } from "@/components/theme-toggle";
import { activeHref, NAV } from "@/lib/nav";

function currentLabel(pathname: string): string {
  const href = activeHref(pathname);
  for (const group of NAV) {
    const item = group.items.find((i) => i.href === href);
    if (item) return item.label;
  }
  return "Kcatta";
}

/** Sticky top bar: sidebar toggle, current-section title, theme switch. */
export function SiteHeader() {
  const pathname = usePathname();
  return (
    <header className="bg-background/80 sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b px-4 backdrop-blur-sm">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
      <span className="text-sm font-medium">{currentLabel(pathname)}</span>
      <div className="ml-auto flex items-center gap-1">
        <ThemeToggle />
      </div>
    </header>
  );
}
