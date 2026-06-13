import { Badge } from "@/components/ui/badge";
import type { ScanJobState } from "@/lib/contracts";
import { STATE_META } from "@/lib/meta";
import { cn } from "@/lib/utils";

/** Scan-job lifecycle pill (`排队中`/`执行中`/`成功`/`失败`), with a live pulse while running. */
export function StateBadge({ state, className }: { state: ScanJobState; className?: string }) {
  const meta = STATE_META[state];
  return (
    <Badge variant={meta.variant} className={cn("gap-1.5", className)}>
      <span
        className={cn(
          "size-1.5 rounded-full",
          meta.dot,
          state === "running" && "animate-pulse",
        )}
      />
      {meta.label}
    </Badge>
  );
}
