import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FormApiError, listFlowBatches } from "@/lib/api";
import type { FlowBatch, FlowEvent, Severity } from "@/lib/contracts";

export const dynamic = "force-dynamic";

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

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function flowsOf(batch: FlowBatch): FlowEvent[] {
  return batch.flows ?? [];
}

function threatHitCount(batch: FlowBatch): number {
  return flowsOf(batch).filter((f) => (f.threat_intel ?? []).length > 0).length;
}

function worstSeverity(batch: FlowBatch): Severity | null {
  let worst: Severity | null = null;
  for (const flow of flowsOf(batch)) {
    for (const match of flow.threat_intel ?? []) {
      if (worst === null || SEVERITY_RANK[match.severity] > SEVERITY_RANK[worst]) {
        worst = match.severity;
      }
    }
  }
  return worst;
}

function formatEndpoint(ip: string, port: number | null | undefined): string {
  return port != null ? `${ip}:${port}` : ip;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge className={SEVERITY_CLASS[severity]}>{severity}</Badge>;
}

function FilterChip({
  href,
  label,
  active,
}: {
  href: string;
  label: string;
  active: boolean;
}) {
  return (
    <Link href={href}>
      <Badge variant={active ? "default" : "outline"}>{label}</Badge>
    </Link>
  );
}

function FlowRow({ flow }: { flow: FlowEvent }) {
  const hits = flow.threat_intel ?? [];
  return (
    <li className="flex flex-col gap-1 border-t py-2 first:border-t-0">
      <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
        <Badge variant="outline">{flow.proto}</Badge>
        <span>
          {formatEndpoint(flow.src_ip, flow.src_port)} → {formatEndpoint(flow.dst_ip, flow.dst_port)}
        </span>
        {flow.app_proto && <Badge variant="secondary">{flow.app_proto}</Badge>}
      </div>
      {(flow.tls_sni || flow.dns_query) && (
        <div className="text-muted-foreground font-mono text-xs">
          {flow.tls_sni && <span>SNI {flow.tls_sni}</span>}
          {flow.tls_sni && flow.dns_query && " · "}
          {flow.dns_query && <span>DNS {flow.dns_query}</span>}
        </div>
      )}
      {hits.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {hits.map((m) => (
            <Badge key={`${m.indicator_type}:${m.indicator}`} className={SEVERITY_CLASS[m.severity]}>
              {m.indicator_type} {m.indicator}
            </Badge>
          ))}
        </div>
      )}
    </li>
  );
}

function BatchCard({ batch }: { batch: FlowBatch }) {
  const flows = flowsOf(batch);
  const hits = threatHitCount(batch);
  const worst = worstSeverity(batch);
  const preview = flows.slice(0, 5);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-base">
          <span className="truncate font-mono text-sm">{batch.collector_id}</span>
          {worst && <SeverityBadge severity={worst} />}
        </CardTitle>
        <CardDescription className="flex flex-col gap-1">
          <span>
            <span className="text-muted-foreground">collected </span>
            <span className="font-mono">{formatTimestamp(batch.collected_at)}</span>
          </span>
          <span className="text-muted-foreground/80 truncate font-mono text-xs">
            {batch.batch_id}
          </span>
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="mb-3 flex flex-wrap gap-2">
          <Badge variant="outline">{flows.length} flows</Badge>
          <Badge variant={hits > 0 ? "destructive" : "secondary"}>{hits} IOC hits</Badge>
          <Badge variant="secondary">v{batch.collector_version}</Badge>
        </div>
        {flows.length === 0 ? (
          <p className="text-muted-foreground text-sm">No flows in this batch.</p>
        ) : (
          <>
            <ul className="flex flex-col">
              {preview.map((flow) => (
                <FlowRow key={flow.flow_id} flow={flow} />
              ))}
            </ul>
            {flows.length > preview.length && (
              <p className="text-muted-foreground mt-2 text-xs">
                … +{flows.length - preview.length} more flows
              </p>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function EmptyState() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>No flow batches yet</CardTitle>
        <CardDescription>
          Network flow metadata arrives as FlowBatch envelopes from collector uploads.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="bg-muted overflow-x-auto rounded-md p-3 font-mono text-xs">
          cargo run -p fusion-flow -- --upload http://127.0.0.1:8000
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

function applyThreatFilter(batches: FlowBatch[], threatsOnly: boolean): FlowBatch[] {
  if (!threatsOnly) return batches;
  return batches.filter((b) => threatHitCount(b) > 0);
}

export default async function FlowsPage({
  searchParams,
}: {
  searchParams: Promise<{ threats?: string | string[] }>;
}) {
  const sp = await searchParams;
  const threatsOnly = sp.threats === "1" || sp.threats === "true";

  let batches: FlowBatch[] = [];
  let error: FormApiError | null = null;
  try {
    batches = await listFlowBatches(50);
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  const filtered = applyThreatFilter(batches, threatsOnly);
  const totalFlows = filtered.reduce((n, b) => n + flowsOf(b).length, 0);
  const totalHits = filtered.reduce((n, b) => n + threatHitCount(b), 0);

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <header className="mb-8 flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Network flows</h1>
        <p className="text-muted-foreground text-sm">
          Flow batches ingested from collector, with IOC matches highlighted.
        </p>
      </header>

      {error ? (
        <ErrorState error={error} />
      ) : batches.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground text-xs">show</span>
            <FilterChip href="/flows" label="All batches" active={!threatsOnly} />
            <FilterChip href="/flows?threats=1" label="IOC hits only" active={threatsOnly} />
          </div>

          {filtered.length === 0 ? (
            <p className="text-muted-foreground text-sm">No batches match the current filter.</p>
          ) : (
            <>
              <div className="mb-6 flex flex-wrap gap-2">
                <Badge variant="outline">{filtered.length} batches</Badge>
                <Badge variant="outline">{totalFlows} flows</Badge>
                <Badge variant="outline">{totalHits} IOC hits</Badge>
              </div>
              <div className="grid gap-4">
                {filtered.map((batch) => (
                  <BatchCard key={batch.batch_id} batch={batch} />
                ))}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
