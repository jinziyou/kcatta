import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/lib/contracts";
import { SEVERITY_META } from "@/lib/meta";
import { cn } from "@/lib/utils";

/** Solid, severity-colored pill (`严重`/`高危`/…). */
export function SeverityBadge({
  severity,
  count,
  className,
}: {
  severity: Severity;
  count?: number;
  className?: string;
}) {
  const meta = SEVERITY_META[severity];
  return (
    <Badge className={cn(meta.badge, className)}>
      {meta.label}
      {count != null && <span className="ml-1 tabular-nums">{count}</span>}
    </Badge>
  );
}

/** A small severity dot, for dense rows/legends. */
export function SeverityDot({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn("inline-block size-2 shrink-0 rounded-full", SEVERITY_META[severity].dot, className)}
    />
  );
}
