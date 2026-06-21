import type { LucideIcon } from "lucide-react";

import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * 方案 A 指挥中心 · KPI 卡:标签 + 强调色图标片,大号数值,可选趋势 + 副标签。
 * 向后兼容原有 label/value/sublabel/icon/accent 调用。
 */
export function Stat({
  label,
  value,
  sublabel,
  icon: Icon,
  accent,
  delta,
  className,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  sublabel?: React.ReactNode;
  icon?: LucideIcon;
  accent?: string;
  delta?: { value: React.ReactNode; dir?: "up" | "down" | "flat" };
  className?: string;
}) {
  const display = typeof value === "number" ? value.toLocaleString() : value;
  return (
    <Card size="sm" className={cn("gap-1.5 p-4", className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-muted-foreground text-sm">{label}</span>
        {Icon && (
          <span className="bg-primary/10 text-primary flex size-7 shrink-0 items-center justify-center rounded-md">
            <Icon className={cn("size-4", accent)} />
          </span>
        )}
      </div>
      <div className={cn("text-2xl font-semibold tabular-nums tracking-tight", !Icon && accent)}>{display}</div>
      {(delta || sublabel) && (
        <div className="flex items-center gap-2">
          {delta && (
            <span
              className={cn(
                "inline-flex items-center gap-0.5 text-xs font-medium tabular-nums",
                delta.dir === "down"
                  ? "text-destructive"
                  : delta.dir === "flat"
                    ? "text-muted-foreground"
                    : "text-emerald-600 dark:text-emerald-400",
              )}
            >
              {delta.dir === "down" ? "▼" : delta.dir === "flat" ? "•" : "▲"} {delta.value}
            </span>
          )}
          {sublabel && <span className="text-muted-foreground text-xs">{sublabel}</span>}
        </div>
      )}
    </Card>
  );
}
