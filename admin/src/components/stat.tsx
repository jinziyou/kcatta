import type { LucideIcon } from "lucide-react";

import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/** Compact KPI tile: label, big value, optional icon + sublabel. */
export function Stat({
  label,
  value,
  sublabel,
  icon: Icon,
  accent,
  className,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  sublabel?: React.ReactNode;
  icon?: LucideIcon;
  accent?: string;
  className?: string;
}) {
  return (
    <Card size="sm" className={cn("gap-2 p-4", className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-muted-foreground text-sm">{label}</span>
        {Icon && <Icon className={cn("size-4", accent ?? "text-muted-foreground")} />}
      </div>
      <div className="text-2xl font-semibold tabular-nums tracking-tight">{value}</div>
      {sublabel && <div className="text-muted-foreground text-xs">{sublabel}</div>}
    </Card>
  );
}
