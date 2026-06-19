import { Network } from "lucide-react";

import { CopyableId } from "@/components/copy-button";
import { FilterChip } from "@/components/filter-chip";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState, ErrorState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AnalyzerApiError, listTraceBatches } from "@/lib/api";
import type { TraceBatch, TraceEvent, Severity, ThreatMatch } from "@/lib/contracts";
import { endpoint, fmtBytes } from "@/lib/format";
import { severityRank } from "@/lib/meta";

export const dynamic = "force-dynamic";

const TRACE_PREVIEW = 8;

function eventsOf(batch: TraceBatch): TraceEvent[] {
  return batch.events ?? [];
}

function hitsOf(ev: TraceEvent): ThreatMatch[] {
  return ev.threat_intel ?? [];
}

/** Traces in this batch that carry at least one IOC match. */
function threatHitCount(batch: TraceBatch): number {
  return eventsOf(batch).filter((f) => hitsOf(f).length > 0).length;
}

/** Most severe IOC severity across all events in a batch, if any. */
function worstSeverity(batch: TraceBatch): Severity | null {
  let worst: Severity | null = null;
  for (const ev of eventsOf(batch)) {
    for (const match of hitsOf(ev)) {
      if (worst === null || severityRank(match.severity) > severityRank(worst)) {
        worst = match.severity;
      }
    }
  }
  return worst;
}

/** Application-layer hint: prefer app_proto, then TLS SNI, then DNS query. */
function appLayer(ev: TraceEvent): string | null {
  return ev.app_proto || ev.tls_sni || ev.dns_query || null;
}

function TraceRow({ ev }: { ev: TraceEvent }) {
  const hits = hitsOf(ev);
  const app = appLayer(ev);
  return (
    <TableRow>
      <TableCell className="align-top">
        <Badge variant="outline" className="font-mono text-[11px] uppercase">
          {ev.proto}
        </Badge>
      </TableCell>
      <TableCell className="font-mono text-xs align-top whitespace-nowrap">
        {endpoint(ev.src_ip, ev.src_port)}
        <span className="text-muted-foreground"> → </span>
        {endpoint(ev.dst_ip, ev.dst_port)}
      </TableCell>
      <TableCell className="text-muted-foreground hidden font-mono text-xs align-top sm:table-cell">
        {app ? <span className="block max-w-[16rem] truncate">{app}</span> : "—"}
      </TableCell>
      <TableCell className="text-muted-foreground hidden font-mono text-xs align-top whitespace-nowrap md:table-cell">
        ↑{fmtBytes(ev.bytes_sent)} / ↓{fmtBytes(ev.bytes_recv)}
      </TableCell>
      <TableCell className="align-top">
        {hits.length === 0 ? (
          <span className="text-muted-foreground text-xs">—</span>
        ) : (
          <div className="flex flex-col gap-1">
            {hits.map((m) => (
              <span
                key={`${m.indicator_type}:${m.indicator}`}
                className="flex items-center gap-1.5"
              >
                <SeverityBadge severity={m.severity} />
                <span className="text-muted-foreground font-mono text-[11px]">
                  {m.indicator_type}
                </span>
                <span className="block max-w-[12rem] truncate font-mono text-xs">
                  {m.indicator}
                </span>
              </span>
            ))}
          </div>
        )}
      </TableCell>
    </TableRow>
  );
}

function BatchCard({ batch }: { batch: TraceBatch }) {
  const events = eventsOf(batch);
  const hits = threatHitCount(batch);
  const worst = worstSeverity(batch);
  const preview = events.slice(0, TRACE_PREVIEW);
  const overflow = events.length - preview.length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-base">
          <span className="truncate font-mono text-sm">{batch.collector_id}</span>
          {worst && <SeverityBadge severity={worst} />}
        </CardTitle>
        <CardDescription>
          <CopyableId value={batch.batch_id} />
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline">{events.length} 条追踪</Badge>
          <Badge variant={hits > 0 ? "destructive" : "secondary"}>命中 {hits}</Badge>
          <Badge variant="secondary" className="font-mono">
            {batch.collector_version}
          </Badge>
        </div>

        {events.length === 0 ? (
          <p className="text-muted-foreground text-sm">本批次没有流记录。</p>
        ) : (
          <div className="overflow-hidden rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/40 hover:bg-muted/40">
                  <TableHead className="w-16">协议</TableHead>
                  <TableHead>源 → 目的</TableHead>
                  <TableHead className="hidden sm:table-cell">应用层</TableHead>
                  <TableHead className="hidden md:table-cell">流量</TableHead>
                  <TableHead>IOC</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {preview.map((ev) => (
                  <TraceRow key={ev.trace_id} ev={ev} />
                ))}
                {overflow > 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell
                      colSpan={5}
                      className="text-muted-foreground text-center text-xs"
                    >
                      … 还有 {overflow} 条
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default async function TracesPage({
  searchParams,
}: {
  searchParams: Promise<{ threats?: string | string[] }>;
}) {
  const sp = await searchParams;
  const threatsOnly = sp.threats === "1" || sp.threats === "true";

  let batches: TraceBatch[] = [];
  let error: AnalyzerApiError | null = null;
  try {
    batches = await listTraceBatches(50);
  } catch (err) {
    error =
      err instanceof AnalyzerApiError
        ? err
        : new AnalyzerApiError(err instanceof Error ? err.message : String(err));
  }

  const filtered = threatsOnly
    ? batches.filter((b) => threatHitCount(b) > 0)
    : batches;
  const totalTraces = filtered.reduce((n, b) => n + eventsOf(b).length, 0);
  const totalHits = filtered.reduce((n, b) => n + threatHitCount(b), 0);

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="网络流量"
        description="collector 上传的流量批次，提取会话特征并做 IOC 初筛，命中威胁情报的会话会被高亮标记。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : batches.length === 0 ? (
        <EmptyState
          icon={Network}
          title="还没有流量批次"
          description="在目标上执行流量采集任务后，collector 会以 TraceBatch 形式上传会话特征，记录会出现在这里。"
        />
      ) : (
        <div className="flex flex-col gap-6">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground text-xs">筛选</span>
            <FilterChip href="/traces" label="全部" active={!threatsOnly} />
            <FilterChip href="/traces?threats=1" label="仅 IOC 命中" active={threatsOnly} />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="secondary">{filtered.length} 批次</Badge>
            <Badge variant="secondary">{totalTraces} 条追踪</Badge>
            <Badge variant={totalHits > 0 ? "destructive" : "secondary"}>
              IOC 命中 {totalHits}
            </Badge>
          </div>

          {filtered.length === 0 ? (
            <EmptyState
              icon={Network}
              title="没有匹配的批次"
              description="当前筛选条件下没有命中 IOC 的流量批次。"
            />
          ) : (
            <div className="flex flex-col gap-4">
              {filtered.map((batch) => (
                <BatchCard key={batch.batch_id} batch={batch} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
