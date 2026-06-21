"use client";

import { Bell, ChevronDown, Search } from "lucide-react";
import { usePathname } from "next/navigation";

import { ThemeToggle } from "@/components/theme-toggle";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { activeHref, BRAND, NAV } from "@/lib/nav";

function currentLabel(pathname: string): string {
  const href = activeHref(pathname);
  for (const group of NAV) {
    const item = group.items.find((i) => i.href === href);
    if (item) return item.label;
  }
  return BRAND.name;
}

/** A「指挥中心」顶栏:品牌面包屑 + 全局搜索 + 时间范围 + 环境 + 通知 + 主题 + 头像。 */
export function SiteHeader() {
  const pathname = usePathname();
  const label = currentLabel(pathname);
  return (
    <header className="bg-background/80 sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b px-3 backdrop-blur-sm sm:px-4">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
      <nav className="flex items-center gap-1.5 text-sm">
        <span className="text-muted-foreground hidden sm:inline">{BRAND.name}</span>
        <span className="text-muted-foreground hidden sm:inline">/</span>
        <span className="font-medium">{label}</span>
      </nav>

      <button
        type="button"
        className="text-muted-foreground bg-muted/50 hover:bg-muted ml-4 hidden h-8 w-64 items-center gap-2 rounded-lg border px-2.5 text-sm transition-colors lg:flex"
      >
        <Search className="size-4 shrink-0" />
        <span className="truncate">搜索资产、漏洞、告警…</span>
        <kbd className="bg-background text-muted-foreground ml-auto rounded border px-1.5 font-mono text-[10px] leading-5">
          ⌘K
        </kbd>
      </button>

      <div className="ml-auto flex items-center gap-1.5">
        <Button variant="outline" size="sm" className="hidden md:inline-flex">
          近 7 天
          <ChevronDown className="size-3.5" />
        </Button>
        <Badge variant="outline" className="hidden md:inline-flex">
          本网段
        </Badge>
        <Button variant="ghost" size="icon" aria-label="通知">
          <Bell className="size-4" />
        </Button>
        <ThemeToggle />
        <div className="bg-primary/15 text-primary ml-1 flex size-8 items-center justify-center rounded-full text-xs font-semibold">
          LP
        </div>
      </div>
    </header>
  );
}
