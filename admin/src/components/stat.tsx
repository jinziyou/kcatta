import type { LucideIcon } from "lucide-react";

import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * Editorial KPI tile. `label` is printed as a `.lp-tag` classification stamp
 * (optionally with a leading `swatch` color), the `value` in the serif display
 * face at a large tabular size, then an optional mono `delta` and a 3px brand
 * progress rail (`progress` 0–100). `icon`/`accent`/`sublabel` are kept for
 * backward compatibility with existing call sites.
 */
export function Stat({
  label,
  value,
  sublabel,
  icon: Icon,
  accent,
  swatch,
  delta,
  deltaUp = false,
  progress,
  className,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  sublabel?: React.ReactNode;
  icon?: LucideIcon;
  accent?: string;
  /** CSS color for the leading `.lp-tag` swatch (e.g. `var(--team-blue)`). */
  swatch?: string;
  /** Optional change indicator, e.g. `↑ 3`. */
  delta?: React.ReactNode;
  /** Render the delta in the success hue (for positive movement). */
  deltaUp?: boolean;
  /** 0–100; renders the bottom brand progress rail when set. */
  progress?: number;
  className?: string;
}) {
  const pct = progress == null ? null : Math.max(0, Math.min(100, progress));
  return (
    <Card size="sm" className={cn("gap-0 p-4 transition-colors", className)}>
      <div className="mb-3.5 flex items-center justify-between gap-2">
        <span className="lp-tag">
          {swatch && <span className="swatch" style={{ background: swatch }} />}
          {label}
        </span>
        {Icon && <Icon className={cn("size-4", accent ?? "text-muted-foreground")} />}
      </div>
      <div className="font-heading text-3xl leading-none font-semibold tracking-tight tabular-nums">
        {value}
      </div>
      {(delta || sublabel) && (
        <div className="lp-mono text-muted-foreground mt-2.5 flex items-center gap-1.5 text-[0.6875rem]">
          {delta && <span className={cn("font-medium", deltaUp && "text-ok")}>{delta}</span>}
          {sublabel && <span>{sublabel}</span>}
        </div>
      )}
      {pct != null && (
        <div className="bg-rule-soft mt-3 h-[3px] overflow-hidden rounded-full">
          <div className="bg-brand h-full rounded-full" style={{ width: `${pct}%` }} />
        </div>
      )}
    </Card>
  );
}
