import type { AlertStatus } from "@/lib/contracts";
import { ALERT_STATUS_META } from "@/lib/meta";
import { cn } from "@/lib/utils";

/**
 * Alert workflow status marker: small square dot + mono uppercase label
 * (`待处理`/`已确认`/`已关闭`), dossier-style — no solid pill.
 */
export function AlertStatusBadge({
  status,
  className,
}: {
  status: AlertStatus;
  className?: string;
}) {
  const meta = ALERT_STATUS_META[status] ?? ALERT_STATUS_META.open;
  return (
    <span
      className={cn(
        "lp-mono inline-flex items-center gap-1.5 text-[0.625rem] font-medium tracking-[0.12em] whitespace-nowrap uppercase",
        meta.text,
        className,
      )}
    >
      <span className={cn("size-[6px] shrink-0 rounded-[1px]", meta.dot)} aria-hidden />
      {meta.label}
    </span>
  );
}
