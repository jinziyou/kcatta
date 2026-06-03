import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FormApiError, listAlerts } from "@/lib/api";
import type { Alert, AlertStatus, Severity } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-black",
  low: "bg-slate-300 text-black",
  info: "bg-slate-200 text-black",
};

const STATUS_ORDER: AlertStatus[] = ["open", "acknowledged", "closed"];

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

function bySeverity(a: Alert, b: Alert): number {
  const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (rank !== 0) return rank;
  return b.score - a.score;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge className={SEVERITY_CLASS[severity]}>{severity}</Badge>;
}

function StatusBadge({ status }: { status: AlertStatus }) {
  return <Badge className={STATUS_CLASS[status]}>{status}</Badge>;
}

function parseMinSeverity(value: string | undefined): Severity | null {
  return value && SEVERITY_ORDER.includes(value as Severity) ? (value as Severity) : null;
}

function parseStatus(value: string | undefined): AlertStatus | null {
  return value && STATUS_ORDER.includes(value as AlertStatus) ? (value as AlertStatus) : null;
}

function buildFilterHref(severity: Severity | null, status: AlertStatus | null): string {
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  const q = params.toString();
  return q ? `/alerts?${q}` : "/alerts";
}

function FilterChip({
  href,
  label,
  active,
  className,
}: {
  href: string;
  label: string;
  active: boolean;
  className?: string;
}) {
  return (
    <Link href={href}>
      <Badge variant={active ? "default" : "outline"} className={active ? className : undefined}>
        {label}
      </Badge>
    </Link>
  );
}

function FilterBar({
  severity,
  status,
}: {
  severity: Severity | null;
  status: AlertStatus | null;
}) {
  return (
    <div className="mb-4 flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground text-xs">min severity</span>
        <FilterChip href={buildFilterHref(null, status)} label="All" active={severity === null} />
        {SEVERITY_ORDER.map((s) => (
          <FilterChip
            key={s}
            href={buildFilterHref(s, status)}
            label={s}
            active={severity === s}
            className={SEVERITY_CLASS[s]}
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground text-xs">status</span>
        <FilterChip href={buildFilterHref(severity, null)} label="All" active={status === null} />
        {STATUS_ORDER.map((s) => (
          <FilterChip
            key={s}
            href={buildFilterHref(severity, s)}
            label={s}
            active={status === s}
            className={STATUS_CLASS[s]}
          />
        ))}
      </div>
    </div>
  );
}

function Summary({ alerts }: { alerts: Alert[] }) {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const alert of alerts) {
    counts[alert.severity] += 1;
  }
  return (
    <div className="mb-6 flex flex-wrap items-center gap-2">
      <Badge variant="outline">{alerts.length} alerts</Badge>
      {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
        <Badge key={s} className={SEVERITY_CLASS[s]}>
          {s}: {counts[s]}
        </Badge>
      ))}
    </div>
  );
}

function AlertCard({ alert }: { alert: Alert }) {
  const flowIds = alert.related_flow_ids ?? [];
  const hostIds = alert.related_asset_ids ?? [];
  const status = alert.status ?? "open";

  return (
    <Link href={`/alerts/${encodeURIComponent(alert.alert_id)}`}>
      <Card className="transition-colors hover:bg-muted/30">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-base leading-snug">
          <SeverityBadge severity={alert.severity} />
          <StatusBadge status={status} />
          <Badge variant="secondary">score {alert.score.toFixed(0)}</Badge>
        </CardTitle>
        <CardDescription className="text-foreground/90 text-sm">{alert.title}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        <p className="text-muted-foreground">{alert.description}</p>
        <div className="flex flex-wrap gap-2">
          {hostIds.length > 0 && (
            <Badge variant="outline">{hostIds.length} host(s)</Badge>
          )}
          {flowIds.length > 0 && (
            <Badge variant="outline">{flowIds.length} flow(s)</Badge>
          )}
        </div>
        {(hostIds.length > 0 || flowIds.length > 0) && (
          <div className="text-muted-foreground flex flex-col gap-1 font-mono text-xs">
            {hostIds.slice(0, 3).map((id) => (
              <span key={id}>host {id}</span>
            ))}
            {hostIds.length > 3 && <span>… +{hostIds.length - 3} more hosts</span>}
            {flowIds.slice(0, 2).map((id) => (
              <span key={id}>flow {id}</span>
            ))}
            {flowIds.length > 2 && <span>… +{flowIds.length - 2} more flows</span>}
          </div>
        )}
        <div className="text-muted-foreground/80 flex flex-col gap-0.5 font-mono text-xs">
          <span>created {formatTimestamp(alert.created_at)}</span>
          <span>{alert.alert_id}</span>
        </div>
      </CardContent>
    </Card>
    </Link>
  );
}

function EmptyState() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>No alerts yet</CardTitle>
        <CardDescription>
          Alerts are created when collector flow batches hit threat-intel IOCs and are ingested
          into form.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="bg-muted overflow-x-auto rounded-md p-3 font-mono text-xs">
          cargo run -p collector-cli -- --intel examples/threat-feed.json --upload
          http://127.0.0.1:8000
        </pre>
      </CardContent>
    </Card>
  );
}

function ErrorState({ error }: { error: FormApiError }) {
  return (
    <Card className="border-destructive/40">
      <CardHeader>
        <CardTitle className="text-destructive">Cannot reach form API</CardTitle>
        <CardDescription>{error.message}</CardDescription>
      </CardHeader>
      <CardContent className="text-muted-foreground text-sm">
        Make sure <span className="font-mono">form-api</span> is running and that
        <span className="font-mono"> NEXT_PUBLIC_FORM_BASE_URL</span> points at it.
      </CardContent>
    </Card>
  );
}

function applyMinSeverity(alerts: Alert[], min: Severity | null): Alert[] {
  if (min === null) return alerts;
  const threshold = SEVERITY_RANK[min];
  return alerts.filter((a) => SEVERITY_RANK[a.severity] >= threshold);
}

function applyStatusFilter(alerts: Alert[], status: AlertStatus | null): Alert[] {
  if (status === null) return alerts;
  return alerts.filter((a) => (a.status ?? "open") === status);
}

export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<{ severity?: string | string[]; status?: string | string[] }>;
}) {
  const sp = await searchParams;
  const severityParam = typeof sp.severity === "string" ? sp.severity : undefined;
  const statusParam = typeof sp.status === "string" ? sp.status : undefined;
  const activeSeverity = parseMinSeverity(severityParam);
  const activeStatus = parseStatus(statusParam);

  let alerts: Alert[] = [];
  let error: FormApiError | null = null;
  try {
    alerts = await listAlerts(50);
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  const filtered = applyStatusFilter(
    applyMinSeverity(alerts, activeSeverity),
    activeStatus,
  ).sort(bySeverity);

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <header className="mb-8 flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Alerts</h1>
        <p className="text-muted-foreground text-sm">
          IOC correlation alerts from ingested flow batches, newest first from form.
        </p>
      </header>

      {error ? (
        <ErrorState error={error} />
      ) : alerts.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <FilterBar severity={activeSeverity} status={activeStatus} />
          {filtered.length === 0 ? (
            <p className="text-muted-foreground text-sm">No alerts match the current filters.</p>
          ) : (
            <>
              <Summary alerts={filtered} />
              <div className="grid gap-4">
                {filtered.map((alert) => (
                  <AlertCard key={alert.alert_id} alert={alert} />
                ))}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
