import { Badge } from "@/components/ui/badge";
import type { AlertStatus } from "@/lib/contracts";
import { ALERT_STATUS_META } from "@/lib/meta";

/** Alert workflow status pill (`待处理`/`已确认`/`已关闭`). */
export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  const meta = ALERT_STATUS_META[status] ?? ALERT_STATUS_META.open;
  return <Badge variant={meta.variant}>{meta.label}</Badge>;
}
