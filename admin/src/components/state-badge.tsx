import type { ScanJobState } from "@/lib/contracts";
import { STATE_META } from "@/lib/meta";
import { cn } from "@/lib/utils";

/**
 * Scan-job lifecycle marker: small square dot + mono uppercase label
 * (`排队中`/`执行中`/`成功`/`失败`), with a live pulse while running.
 */
export function StateBadge({ state, className }: { state: ScanJobState; className?: string }) {
  const meta = STATE_META[state];
  return (
    <span
      className={cn(
        "lp-mono inline-flex items-center gap-1.5 text-[0.625rem] font-medium tracking-[0.12em] whitespace-nowrap uppercase",
        className,
      )}
    >
      <span
        className={cn(
          "size-[6px] shrink-0 rounded-[1px]",
          meta.dot,
          (state === "running" || state === "cancelling") && "animate-pulse",
        )}
        aria-hidden
      />
      {meta.label}
    </span>
  );
}
