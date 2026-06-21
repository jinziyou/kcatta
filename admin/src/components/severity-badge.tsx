import type { Severity } from "@/lib/contracts";
import { SEVERITY_META } from "@/lib/meta";
import { cn } from "@/lib/utils";

/**
 * Editorial severity marker: a small `--sev-*`-colored dot + mono uppercase
 * label, never a solid high-saturation pill.
 */
export function SeverityBadge({
  severity,
  count,
  className,
}: {
  severity: Severity;
  count?: number;
  className?: string;
}) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.info;
  return (
    <span
      className={cn(
        "lp-mono inline-flex items-center gap-1.5 text-[0.625rem] font-medium tracking-[0.12em] whitespace-nowrap uppercase",
        meta.text,
        className,
      )}
    >
      <span className={cn("size-[7px] shrink-0 rounded-full", meta.dot)} aria-hidden />
      {meta.label}
      {count != null && <span className="tabular-nums">{count}</span>}
    </span>
  );
}
