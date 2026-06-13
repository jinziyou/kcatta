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
import { FusionApiError, listFlowBatches } from "@/lib/api";
import type { FlowBatch, FlowEvent, Severity, ThreatMatch } from "@/lib/contracts";
import { endpoint, fmtBytes } from "@/lib/format";
import { severityRank } from "@/lib/meta";

export const dynamic = "force-dynamic";

const FLOW_PREVIEW = 8;

function flowsOf(batch: FlowBatch): FlowEvent[] {
  return batch.flows ?? [];
}

function hitsOf(flow: FlowEvent): ThreatMatch[] {
  return flow.threat_intel ?? [];
}

/** Flows in this batch that carry at least one IOC match. */
function threatHitCount(batch: FlowBatch): number {
  return flowsOf(batch).filter((f) => hitsOf(f).length > 0).length;
}

/** Most severe IOC severity across all flows in a batch, if any. */
function worstSeverity(batch: FlowBatch): Severity | null {
  let worst: Severity | null = null;
  for (const flow of flowsOf(batch)) {
    for (const match of hitsOf(flow)) {
      if (worst === null || severityRank(match.severity) > severityRank(worst)) {
        worst = match.severity;
      }
    }
  }
  return worst;
}

/** Application-layer hint: prefer app_proto, then TLS SNI, then DNS query. */
function appLayer(flow: FlowEvent): string | null {
  return flow.app_proto || flow.tls_sni || flow.dns_query || null;
}

function FlowRow({ flow }: { flow: FlowEvent }) {
  const hits = hitsOf(flow);
  const app = appLayer(flow);
  return (
    <TableRow>
      <TableCell className="align-top">
        <Badge variant="outline" className="font-mono text-[11px] uppercase">
          {flow.proto}
        </Badge>
      </TableCell>
      <TableCell className="font-mono text-xs align-top whitespace-nowrap">
        {endpoint(flow.src_ip, flow.src_port)}
        <span className="text-muted-foreground"> → </span>
        {endpoint(flow.dst_ip, flow.dst_port)}
      </TableCell>
      <TableCell className="text-muted-foreground hidden font-mono text-xs align-top sm:table-cell">
        {app ? <span className="block max-w-[16rem] truncate">{app}</span> : "—"}
      </TableCell>
      <TableCell className="text-muted-foreground hidden font-mono text-xs align-top whitespace-nowrap md:table-cell">
        ↑{fmtBytes(flow.bytes_sent)} / ↓{fmtBytes(flow.bytes_recv)}
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

function BatchCard({ batch }: { batch: FlowBatch }) {
  const flows = flowsOf(batch);
  const hits = threatHitCount(batch);
  const worst = worstSeverity(batch);
  const preview = flows.slice(0, FLOW_PREVIEW);
  const overflow = flows.length - preview.length;

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
          <Badge variant="outline">{flows.length} 条流</Badge>
          <Badge variant={hits > 0 ? "destructive" : "secondary"}>命中 {hits}</Badge>
          <Badge variant="secondary" className="font-mono">
            {batch.collector_version}
          </Badge>
        </div>

        {flows.length === 0 ? (
          <p className="text-muted-foreground text-sm">本批次没有流记录。</p>
        ) : (
          <div className="overflow-hidden rounded-xl border">
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
                {preview.map((flow) => (
                  <FlowRow key={flow.flow_id} flow={flow} />
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

export default async function FlowsPage({
  searchParams,
}: {
  searchParams: Promise<{ threats?: string | string[] }>;
}) {
  const sp = await searchParams;
  const threatsOnly = sp.threats === "1" || sp.threats === "true";

  let batches: FlowBatch[] = [];
  let error: FusionApiError | null = null;
  try {
    batches = await listFlowBatches(50);
  } catch (err) {
    error =
      err instanceof FusionApiError
        ? err
        : new FusionApiError(err instanceof Error ? err.message : String(err));
  }

  const filtered = threatsOnly
    ? batches.filter((b) => threatHitCount(b) > 0)
    : batches;
  const totalFlows = filtered.reduce((n, b) => n + flowsOf(b).length, 0);
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
          description="在目标上执行流量采集任务后，collector 会以 FlowBatch 形式上传会话特征，记录会出现在这里。"
        />
      ) : (
        <div className="flex flex-col gap-6">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground text-xs">筛选</span>
            <FilterChip href="/flows" label="全部" active={!threatsOnly} />
            <FilterChip href="/flows?threats=1" label="仅 IOC 命中" active={threatsOnly} />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="secondary">{filtered.length} 批次</Badge>
            <Badge variant="secondary">{totalFlows} 条流</Badge>
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
