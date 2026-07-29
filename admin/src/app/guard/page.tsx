import { Server, ShieldAlert, TriangleAlert } from "lucide-react";
import Link from "next/link";

import { CopyableId } from "@/components/copy-button";
import { PageHeader } from "@/components/page-header";
import { PageNav } from "@/components/page-nav";
import { RevealList } from "@/components/reveal";
import { SeverityBadge } from "@/components/severity-badge";
import { Stat } from "@/components/stat";
import { EmptyState, ErrorState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
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
import { FormApiError, listGuardEventsCursor } from "@/lib/api";
import type { GuardEventBatch, GuardEvents, Severity } from "@/lib/contracts";
import { endpoint, fmtTimestamp } from "@/lib/format";
import {
  cursorNavigation,
  parseCursor,
  parseCursorTrail,
  parsePage,
  REPORT_PAGE_SIZE,
} from "@/lib/pagination";

export const dynamic = "force-dynamic";

type GuardEvent = GuardEvents[number];

/** Pull the discriminator out of an event whose `kind` field is schema-optional. */
function eventKind(event: GuardEvent): string {
  return event.kind ?? "—";
}

/** The most useful per-kind detail, rendered as monospace technical text. */
function eventDetail(event: GuardEvent): string {
  switch (event.kind) {
    case "fim":
      return `${event.change_type} · ${event.path}`;
    case "malware":
      return `${event.signature} · ${event.path}`;
    case "process":
      return `${event.behavior} · ${event.process_name}(${event.pid})`;
    case "network":
      return `${event.category} · ${event.indicator} → ${endpoint(event.dst_ip, event.dst_port)}`;
    case "ids":
      return `${event.signature_name} · ${endpoint(event.src_ip, event.src_port)} → ${endpoint(event.dst_ip, event.dst_port)}`;
    default:
      return "—";
  }
}

function eventMetadata(event: GuardEvent): string[] {
  switch (event.kind) {
    case "fim":
      return [
        `变更前 SHA-256 ${event.hash_before ?? "—"}`,
        `变更后 SHA-256 ${event.hash_after ?? "—"}`,
      ];
    case "malware":
      return [`检测器 ${event.source}`, `触发进程 PID ${event.process_id ?? "—"}`];
    case "process":
      return [
        `规则 ${event.rule_id}`,
        `父进程 ${event.parent_name ?? "—"}(${event.parent_pid ?? "—"})`,
        `证据 ${event.evidence ?? "—"}`,
      ];
    case "network":
      return [
        `IOC ${event.indicator_type}:${event.indicator}`,
        `情报源 ${event.source}`,
        `${event.proto.toUpperCase()} ${endpoint(event.src_ip, event.src_port)} → ${endpoint(event.dst_ip, event.dst_port)}`,
      ];
    case "ids":
      return [
        `规则 SID ${event.signature_id}`,
        `${event.proto.toUpperCase()} ${endpoint(event.src_ip, event.src_port)} → ${endpoint(event.dst_ip, event.dst_port)}`,
      ];
    default:
      return [];
  }
}

function EventsTable({ events }: { events: GuardEvent[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/40 hover:bg-muted/40">
            <TableHead>类型</TableHead>
            <TableHead>严重度</TableHead>
            <TableHead className="hidden md:table-cell">时间</TableHead>
            <TableHead className="hidden sm:table-cell">动作</TableHead>
            <TableHead className="hidden lg:table-cell">结果</TableHead>
            <TableHead>详情</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {events.map((event) => (
            <TableRow key={event.event_id}>
              <TableCell>
                <Badge variant="secondary" className="font-mono">
                  {eventKind(event)}
                </Badge>
              </TableCell>
              <TableCell>
                <SeverityBadge severity={event.severity} />
              </TableCell>
              <TableCell className="text-muted-foreground hidden font-mono text-xs md:table-cell">
                {fmtTimestamp(event.timestamp)}
              </TableCell>
              <TableCell className="hidden sm:table-cell">
                <Badge variant="outline" className="font-mono">
                  {event.action_taken}
                </Badge>
              </TableCell>
              <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                {event.outcome}
              </TableCell>
              <TableCell className="min-w-80 max-w-xl font-mono text-xs">
                <span className="block break-all font-medium">{eventDetail(event)}</span>
                {eventMetadata(event).map((detail) => (
                  <span key={detail} className="text-muted-foreground block break-all">
                    {detail}
                  </span>
                ))}
                <span className="text-muted-foreground block break-all">事件 ID {event.event_id}</span>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function BatchCard({ batch }: { batch: GuardEventBatch }) {
  const events = batch.events ?? [];
  return (
    <Card size="sm" className="gap-4">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          <span className="font-mono">{batch.host_id}</span>
          <Badge variant="outline" className="tabular-nums">
            {events.length} 事件
          </Badge>
        </CardTitle>
        <CardDescription className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          <CopyableId value={batch.batch_id} />
          <span className="font-mono">采集于 {fmtTimestamp(batch.collected_at)}</span>
          <span className="font-mono">agent v{batch.agent_version}</span>
          {batch.source_agent_id && <span className="font-mono">来源 Agent {batch.source_agent_id}</span>}
          {batch.source_target_id && <span className="font-mono">来源目标 {batch.source_target_id}</span>}
        </CardDescription>
      </CardHeader>
      {events.length > 0 && <EventsTable events={events} />}
    </Card>
  );
}

export default async function GuardPage({
  searchParams,
}: {
  searchParams: Promise<{
    host?: string;
    page?: string | string[];
    cursor?: string | string[];
    trail?: string | string[];
  }>;
}) {
  const params = await searchParams;
  const host = params.host;
  const page = parsePage(params.page);
  const cursor = parseCursor(params.cursor);
  const trail = parseCursorTrail(params.trail);

  let batches: GuardEventBatch[] = [];
  let nextCursor: string | null = null;
  let error: FormApiError | null = null;
  try {
    const result = await listGuardEventsCursor(cursor, host, REPORT_PAGE_SIZE);
    nextCursor = result.nextCursor;
    batches = result.items;
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  const allEvents = batches.reduce((n, b) => n + (b.events?.length ?? 0), 0);
  const sevCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const b of batches) for (const e of b.events ?? []) sevCounts[e.severity] += 1;
  const hostSet = new Set(batches.map((b) => b.host_id));
  const { previousHref, nextHref } = cursorNavigation(
    "/guard",
    page,
    cursor,
    nextCursor,
    trail,
    { host: host ?? null },
  );

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="防护事件"
        description={
          host ? (
            <>
              <span className="font-mono">agent-respond</span> 实时防护上报的事件，已按主机{" "}
              <span className="font-mono">{host}</span> 过滤，最新批次在前。
            </>
          ) : (
            <>
              <span className="font-mono">agent-respond</span>{" "}
              实时防护上报的事件，按主机分批，最新批次在前。
            </>
          )
        }
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : batches.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="暂无防护事件"
          description={
            page > 0
              ? "这一页没有防护事件，请返回上一页。"
              : "尚未收到任何 guard 上报。请在扫描页下发 guard 任务，部署常驻防护进程后事件会出现在这里。"
          }
        >
          {page > 0 ? (
            <PageNav page={page} count={0} previousHref={previousHref} />
          ) : (
            <Button render={<Link href="/scans" />}>前往下发 guard 任务</Button>
          )}
        </EmptyState>
      ) : (
        <div className="flex flex-col gap-6">
          {/* KPI 概览条 */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              icon={ShieldAlert}
              label="防护事件"
              value={allEvents}
              sublabel={`本页 ${batches.length} 个批次`}
            />
            <Stat icon={ShieldAlert} label="严重" value={sevCounts.critical} accent="text-red-600" sublabel="critical" />
            <Stat icon={TriangleAlert} label="高危" value={sevCounts.high} accent="text-orange-500" sublabel="high" />
            <Stat icon={Server} label="涉及主机" value={hostSet.size} sublabel="去重主机" />
          </div>

          <RevealList className="flex flex-col gap-4" initial={8} step={8}>
            {batches.map((batch) => (
              <BatchCard key={batch.batch_id} batch={batch} />
            ))}
          </RevealList>

          <PageNav
            page={page}
            count={batches.length}
            previousHref={previousHref}
            nextHref={nextHref}
          />
        </div>
      )}
    </div>
  );
}
