import { Activity, FileClock, Network, ShieldAlert, TerminalSquare } from "lucide-react";
import Link from "next/link";

import { CopyableId } from "@/components/copy-button";
import { FilterChip } from "@/components/filter-chip";
import { PageHeader } from "@/components/page-header";
import { PageNav } from "@/components/page-nav";
import { RevealList, RevealRows } from "@/components/reveal";
import { SeverityBadge } from "@/components/severity-badge";
import { Stat } from "@/components/stat";
import { EmptyState, ErrorState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FormApiError, getTraceBatchLineage, listTraceBatchesCursor } from "@/lib/api";
import type { LineageResponse } from "@/lib/api";
import type {
  FileTraceEvent,
  ProcessTraceEvent,
  Severity,
  ThreatMatch,
  TraceBatch,
  TraceEvent,
} from "@/lib/contracts";
import { endpoint, fmtBytes, fmtTimestamp } from "@/lib/format";
import { severityRank } from "@/lib/meta";
import {
  cursorNavigation,
  pageHref,
  parseCursor,
  parseCursorTrail,
  parsePage,
  REPORT_PAGE_SIZE,
} from "@/lib/pagination";

export const dynamic = "force-dynamic";

type ThreatBearing = { threat_intel?: ThreatMatch[] };

function hitsOf(event: ThreatBearing): ThreatMatch[] {
  return event.threat_intel ?? [];
}

function allEvents(batch: TraceBatch): ThreatBearing[] {
  return [...(batch.events ?? []), ...(batch.file_events ?? []), ...(batch.process_events ?? [])];
}

/** Number of IOC matches (not merely the number of sessions carrying a match). */
function threatHitCount(batch: TraceBatch): number {
  return allEvents(batch).reduce((count, event) => count + hitsOf(event).length, 0);
}

function worstSeverity(batch: TraceBatch): Severity | null {
  let worst: Severity | null = null;
  for (const event of allEvents(batch)) {
    for (const match of hitsOf(event)) {
      if (worst === null || severityRank(match.severity) > severityRank(worst)) {
        worst = match.severity;
      }
    }
  }
  return worst;
}

function IocMatches({ matches }: { matches: ThreatMatch[] }) {
  if (matches.length === 0) return <span className="text-muted-foreground text-xs">—</span>;
  return (
    <div className="flex min-w-52 flex-col gap-2">
      {matches.map((match, index) => (
        <div key={`${match.indicator_type}:${match.indicator}:${index}`} className="text-xs">
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityBadge severity={match.severity} />
            <Badge variant="outline" className="font-mono text-[10px]">
              {match.indicator_type}
            </Badge>
            <span className="break-all font-mono">{match.indicator}</span>
          </div>
          <p className="text-muted-foreground mt-1 break-words">
            {match.category} · 来源 {match.source}
            {match.description ? ` · ${match.description}` : ""}
          </p>
        </div>
      ))}
    </div>
  );
}

function NetworkRow({ event }: { event: TraceEvent }) {
  return (
    <TableRow>
      <TableCell className="min-w-44 align-top font-mono text-xs">
        <span className="block">{fmtTimestamp(event.start_ts)}</span>
        <span className="text-muted-foreground block">至 {fmtTimestamp(event.end_ts)}</span>
        <span className="text-muted-foreground block break-all" title={event.trace_id}>
          {event.trace_id}
        </span>
      </TableCell>
      <TableCell className="align-top">
        <Badge variant="outline" className="font-mono text-[11px] uppercase">
          {event.proto}
        </Badge>
        <span className="text-muted-foreground mt-1 block break-all font-mono text-[11px]">
          {event.host_id}
        </span>
      </TableCell>
      <TableCell className="min-w-56 align-top font-mono text-xs">
        {endpoint(event.src_ip, event.src_port)}
        <span className="text-muted-foreground"> → </span>
        {endpoint(event.dst_ip, event.dst_port)}
      </TableCell>
      <TableCell className="min-w-48 align-top font-mono text-xs">
        <span className="block">协议 {event.app_proto || "—"}</span>
        <span className="text-muted-foreground block break-all">SNI {event.tls_sni || "—"}</span>
        <span className="text-muted-foreground block break-all">DNS {event.dns_query || "—"}</span>
        <span className="text-muted-foreground block break-all">JA3 {event.ja3 || "—"}</span>
      </TableCell>
      <TableCell className="min-w-40 align-top font-mono text-xs whitespace-nowrap">
        <span className="block">↑{fmtBytes(event.bytes_sent)} / ↓{fmtBytes(event.bytes_recv)}</span>
        <span className="text-muted-foreground block">
          包 ↑{event.packets_sent ?? "—"} / ↓{event.packets_recv ?? "—"}
        </span>
      </TableCell>
      <TableCell className="align-top">
        <IocMatches matches={hitsOf(event)} />
      </TableCell>
    </TableRow>
  );
}

function FileRow({ event }: { event: FileTraceEvent }) {
  return (
    <TableRow>
      <TableCell className="min-w-44 align-top font-mono text-xs">
        <span className="block">{fmtTimestamp(event.ts)}</span>
        <span className="text-muted-foreground block break-all">{event.trace_id}</span>
      </TableCell>
      <TableCell className="align-top">
        <Badge variant="outline" className="font-mono text-[11px] uppercase">
          {event.op}
        </Badge>
        <span className="text-muted-foreground mt-1 block break-all font-mono text-[11px]">
          {event.host_id}
        </span>
      </TableCell>
      <TableCell className="min-w-72 align-top font-mono text-xs">
        <span className="block break-all">{event.path}</span>
        {event.target_path && (
          <span className="text-muted-foreground block break-all">目标 {event.target_path}</span>
        )}
      </TableCell>
      <TableCell className="min-w-40 align-top font-mono text-xs">
        <span className="block">{event.comm} · PID {event.pid}</span>
        <span className="text-muted-foreground block">UID {event.uid ?? "—"}</span>
        <span className="text-muted-foreground block">返回值 {event.ret ?? "—"}</span>
      </TableCell>
      <TableCell className="align-top">
        <IocMatches matches={hitsOf(event)} />
      </TableCell>
    </TableRow>
  );
}

function ProcessRow({ event }: { event: ProcessTraceEvent }) {
  return (
    <TableRow>
      <TableCell className="min-w-44 align-top font-mono text-xs">
        <span className="block">{fmtTimestamp(event.ts)}</span>
        <span className="text-muted-foreground block break-all">{event.trace_id}</span>
      </TableCell>
      <TableCell className="align-top">
        <Badge variant="outline" className="font-mono text-[11px] uppercase">
          {event.event_type}
        </Badge>
        <span className="text-muted-foreground mt-1 block break-all font-mono text-[11px]">
          {event.host_id}
        </span>
      </TableCell>
      <TableCell className="min-w-72 align-top font-mono text-xs">
        <span className="block break-all">{event.exe || event.comm}</span>
        {event.argv && event.argv.length > 0 && (
          <span className="text-muted-foreground block break-all">{event.argv.join(" ")}</span>
        )}
      </TableCell>
      <TableCell className="min-w-48 align-top font-mono text-xs">
        <span className="block">PID {event.pid} · PPID {event.ppid ?? "—"}</span>
        <span className="text-muted-foreground block">UID {event.uid ?? "—"}</span>
        <span className="text-muted-foreground block break-all">cgroup {event.cgroup || "—"}</span>
        <span className="text-muted-foreground block">退出码 {event.exit_code ?? "—"}</span>
      </TableCell>
      <TableCell className="align-top">
        <IocMatches matches={hitsOf(event)} />
      </TableCell>
    </TableRow>
  );
}

function StreamTable({
  kind,
  events,
}: {
  kind: "network" | "file" | "process";
  events: TraceEvent[] | FileTraceEvent[] | ProcessTraceEvent[];
}) {
  const meta = {
    network: { label: "网络流", icon: Network, columns: ["时间 / ID", "协议 / 主机", "源 → 目的", "应用层", "流量", "IOC"] },
    file: { label: "文件操作", icon: FileClock, columns: ["时间 / ID", "操作 / 主机", "路径", "进程 / 返回值", "IOC"] },
    process: { label: "进程生命周期", icon: TerminalSquare, columns: ["时间 / ID", "事件 / 主机", "程序 / 参数", "进程上下文", "IOC"] },
  }[kind];
  const Icon = meta.icon;

  if (events.length === 0) return null;
  return (
    <section className="flex flex-col gap-2">
      <h3 className="flex items-center gap-2 text-sm font-medium">
        <Icon className="text-muted-foreground size-4" />
        {meta.label}
        <Badge variant="outline" className="tabular-nums">{events.length}</Badge>
      </h3>
      <div className="overflow-x-auto rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              {meta.columns.map((column) => <TableHead key={column}>{column}</TableHead>)}
            </TableRow>
          </TableHeader>
          <TableBody>
            <RevealRows colSpan={meta.columns.length} initial={20} step={20}>
              {kind === "network"
                ? (events as TraceEvent[]).map((event) => <NetworkRow key={event.trace_id} event={event} />)
                : kind === "file"
                  ? (events as FileTraceEvent[]).map((event) => <FileRow key={event.trace_id} event={event} />)
                  : (events as ProcessTraceEvent[]).map((event) => <ProcessRow key={event.trace_id} event={event} />)}
            </RevealRows>
          </TableBody>
        </Table>
      </div>
    </section>
  );
}

function BatchCard({ batch }: { batch: TraceBatch }) {
  const networkEvents = batch.events ?? [];
  const fileEvents = batch.file_events ?? [];
  const processEvents = batch.process_events ?? [];
  const hits = threatHitCount(batch);
  const worst = worstSeverity(batch);
  const eventCount = networkEvents.length + fileEvents.length + processEvents.length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-base">
          <span className="truncate font-mono text-sm">{batch.collector_id}</span>
          {worst && <SeverityBadge severity={worst} />}
        </CardTitle>
        <CardDescription className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <CopyableId value={batch.batch_id} />
          <Link
            href={"/traces?batch=" + encodeURIComponent(batch.batch_id)}
            className="hover:text-foreground hover:underline"
          >
            查看完整分片
          </Link>
          <span className="font-mono">采集于 {fmtTimestamp(batch.collected_at)}</span>
          <span className="font-mono">collector v{batch.collector_version}</span>
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline">共 {eventCount} 条</Badge>
          <Badge variant="secondary">网络 {networkEvents.length}</Badge>
          <Badge variant="secondary">文件 {fileEvents.length}</Badge>
          <Badge variant="secondary">进程 {processEvents.length}</Badge>
          <Badge variant={hits > 0 ? "destructive" : "secondary"}>IOC {hits} 项</Badge>
          {batch.source_agent_id && <Badge variant="outline">Agent {batch.source_agent_id}</Badge>}
          {batch.source_target_id && <Badge variant="outline">目标 {batch.source_target_id}</Badge>}
        </div>

        {eventCount === 0 ? (
          <p className="text-muted-foreground text-sm">本批次没有网络、文件或进程事件。</p>
        ) : (
          <>
            <StreamTable kind="network" events={networkEvents} />
            <StreamTable kind="file" events={fileEvents} />
            <StreamTable kind="process" events={processEvents} />
          </>
        )}
      </CardContent>
    </Card>
  );
}

export default async function TracesPage({
  searchParams,
}: {
  searchParams: Promise<{
    threats?: string | string[];
    page?: string | string[];
    batch?: string | string[];
    cursor?: string | string[];
    trail?: string | string[];
  }>;
}) {
  const params = await searchParams;
  const threatsOnly = params.threats === "1" || params.threats === "true";
  const batchId = typeof params.batch === "string" && params.batch ? params.batch : null;
  const page = parsePage(params.page);
  const cursor = parseCursor(params.cursor);
  const trail = parseCursorTrail(params.trail);

  let batches: TraceBatch[] = [];
  let lineage: LineageResponse<TraceBatch> | null = null;
  let nextCursor: string | null = null;
  let error: FormApiError | null = null;
  try {
    if (batchId) {
      lineage = await getTraceBatchLineage(batchId);
      batches = lineage.records;
    } else {
      const result = await listTraceBatchesCursor(cursor, REPORT_PAGE_SIZE);
      nextCursor = result.nextCursor;
      batches = result.items;
    }
  } catch (caught) {
    error = caught instanceof FormApiError
      ? caught
      : new FormApiError(caught instanceof Error ? caught.message : String(caught));
  }

  const filtered = threatsOnly ? batches.filter((batch) => threatHitCount(batch) > 0) : batches;
  const networkCount = batches.reduce((count, batch) => count + (batch.events?.length ?? 0), 0);
  const fileCount = batches.reduce((count, batch) => count + (batch.file_events?.length ?? 0), 0);
  const processCount = batches.reduce((count, batch) => count + (batch.process_events?.length ?? 0), 0);
  const hitCount = batches.reduce((count, batch) => count + threatHitCount(batch), 0);
  const { previousHref, nextHref } = cursorNavigation(
    "/traces",
    page,
    cursor,
    nextCursor,
    trail,
    { threats: threatsOnly ? "1" : null, batch: batchId },
  );

  return (
    <div className="mx-auto w-full max-w-7xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="网络流量"
        description={
          lineage
            ? "正在展示逻辑批次 " + lineage.lineage_id + " 的所有已保留分片。"
            : "完整展示 collector 上传的网络、文件和进程三类事件及其 IOC 证据，支持逐页翻阅历史。"
        }
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : batches.length === 0 ? (
        <EmptyState
          icon={Network}
          title="还没有追踪批次"
          description={page > 0 ? "这一页没有追踪批次，请返回上一页。" : "运行流量或 eBPF 追踪任务后，批次会出现在这里。"}
        >
          {page > 0 && <PageNav page={page} count={0} previousHref={previousHref} />}
        </EmptyState>
      ) : (
        <div className="flex flex-col gap-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <Stat icon={Activity} label="追踪批次" value={batches.length} sublabel="本页" />
            <Stat icon={Network} label="网络流" value={networkCount} sublabel="本页事件" />
            <Stat icon={FileClock} label="文件操作" value={fileCount} sublabel="本页事件" />
            <Stat icon={TerminalSquare} label="进程事件" value={processCount} sublabel="本页事件" />
            <Stat icon={ShieldAlert} label="IOC 命中" value={hitCount} accent={hitCount > 0 ? "text-red-600" : undefined} sublabel="实际匹配项" />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground text-xs">筛选</span>
            <FilterChip
              href={pageHref("/traces", 0, { batch: batchId, threats: null })}
              label="全部"
              active={!threatsOnly}
            />
            <FilterChip
              href={pageHref("/traces", 0, { batch: batchId, threats: "1" })}
              label="仅 IOC 命中"
              active={threatsOnly}
            />
            {batchId && <FilterChip href="/traces" label="返回所有批次" active={false} />}
          </div>

          {lineage && (
            <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/20 p-3 text-sm">
              <Badge variant={lineage.complete === false ? "destructive" : "outline"}>
                已收到 {lineage.received_chunks}/{lineage.expected_chunks ?? "?"} 分片
              </Badge>
              <span className="text-muted-foreground">
                {lineage.complete === true
                  ? "分片完整"
                  : lineage.complete === false
                    ? "存在缺失分片，当前展示并非完整结果"
                    : "上报未声明总分片数，完整性未知"}
              </span>
            </div>
          )}

          {filtered.length === 0 ? (
            <EmptyState icon={Network} title="本页没有匹配的批次" description="可继续翻页，或取消 IOC 筛选。" />
          ) : (
            <RevealList className="flex flex-col gap-4" initial={6} step={6}>
              {filtered.map((batch) => <BatchCard key={batch.batch_id} batch={batch} />)}
            </RevealList>
          )}

          {!batchId && (
            <PageNav
              page={page}
              count={batches.length}
              previousHref={previousHref}
              nextHref={nextHref}
            />
          )}
        </div>
      )}
    </div>
  );
}
