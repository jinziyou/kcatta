import Link from "next/link";
import { notFound } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FormApiError, getAlert } from "@/lib/api";
import type { Alert, AlertStatus, Severity } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-black",
  low: "bg-slate-300 text-black",
  info: "bg-slate-200 text-black",
};

const STATUS_CLASS: Record<AlertStatus, string> = {
  open: "bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-100",
  acknowledged: "bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-100",
  closed: "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-200",
};

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge className={SEVERITY_CLASS[severity]}>{severity}</Badge>;
}

function StatusBadge({ status }: { status: AlertStatus }) {
  return <Badge className={STATUS_CLASS[status]}>{status}</Badge>;
}

function IdList({ label, ids }: { label: string; ids: string[] }) {
  if (ids.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {label} ({ids.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col gap-1 font-mono text-xs">
          {ids.map((id) => (
            <li key={id}>{id}</li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

export default async function AlertPage({
  params,
}: {
  params: Promise<{ alertId: string }>;
}) {
  const { alertId } = await params;

  let alert: Alert;
  try {
    alert = await getAlert(alertId);
  } catch (err) {
    if (err instanceof FormApiError && err.status === 404) {
      notFound();
    }
    throw err;
  }

  const status = alert.status ?? "open";
  const hostIds = alert.related_asset_ids ?? [];
  const flowIds = alert.related_flow_ids ?? [];
  const vulnIds = alert.related_vuln_ids ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <Link
        href="/alerts"
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
      >
        ← Alerts
      </Link>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-base">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={status} />
            <Badge variant="secondary">score {alert.score.toFixed(0)}</Badge>
          </CardTitle>
          <CardDescription className="text-foreground/90 text-sm">{alert.title}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 text-sm">
          <p className="text-muted-foreground">{alert.description}</p>
          <div className="text-muted-foreground/80 flex flex-col gap-0.5 font-mono text-xs">
            <span>created {formatTimestamp(alert.created_at)}</span>
            {alert.updated_at && <span>updated {formatTimestamp(alert.updated_at)}</span>}
            <span>{alert.alert_id}</span>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4">
        <IdList label="Related hosts" ids={hostIds} />
        <IdList label="Related flows" ids={flowIds} />
        <IdList label="Related vulnerabilities" ids={vulnIds} />
      </div>
    </div>
  );
}
