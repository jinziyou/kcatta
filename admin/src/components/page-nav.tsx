import Link from "next/link";

import { Button } from "@/components/ui/button";

/** Backend-driven paging for APIs that expose `limit` + `offset` without totals. */
export function PageNav({
  page,
  count,
  previousHref,
  nextHref,
  ariaLabel = "分页",
}: {
  page: number;
  count: number;
  previousHref?: string;
  nextHref?: string;
  ariaLabel?: string;
}) {
  return (
    <nav
      aria-label={ariaLabel}
      className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/20 px-3 py-2"
    >
      <span className="text-muted-foreground text-xs tabular-nums">
        第 {page + 1} 页 · 本页 {count} 条
      </span>
      <div className="flex items-center gap-2">
        {previousHref ? (
          <Button variant="outline" size="sm" render={<Link href={previousHref} />}>
            上一页
          </Button>
        ) : (
          <Button variant="outline" size="sm" disabled>
            上一页
          </Button>
        )}
        {nextHref ? (
          <Button variant="outline" size="sm" render={<Link href={nextHref} />}>
            下一页（继续加载）
          </Button>
        ) : (
          <Button variant="outline" size="sm" disabled>
            已到最后一页
          </Button>
        )}
      </div>
    </nav>
  );
}
