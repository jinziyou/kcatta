import { Server, ShieldAlert, TriangleAlert } from "lucide-react";
import Link from "next/link";

import { CopyableId } from "@/components/copy-button";
import { PageHeader } from "@/components/page-header";
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
import { AnalyzerApiError, listGuardEvents } from "@/lib/api";
import type { GuardEventBatch, GuardEvents, Severity } from "@/lib/contracts";
import { endpoint, fmtTimestamp } from "@/lib/format";

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

function EventsTable({ events }: { events: GuardEvent[] }) {
  return (
    <div className="overflow-hidden rounded-lg border">
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
              <TableCell className="max-w-[28rem] truncate font-mono text-xs" title={eventDetail(event)}>
                {eventDetail(event)}
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
        </CardDescription>
      </CardHeader>
      {events.length > 0 && <EventsTable events={events} />}
    </Card>
  );
}

export default async function GuardPage({
  searchParams,
}: {
  searchParams: Promise<{ host?: string }>;
}) {
  const { host } = await searchParams;

  let batches: GuardEventBatch[] = [];
  let error: AnalyzerApiError | null = null;
  try {
    batches = await listGuardEvents(host);
  } catch (err) {
    error =
      err instanceof AnalyzerApiError
        ? err
        : new AnalyzerApiError(err instanceof Error ? err.message : String(err));
  }

  const allEvents = batches.reduce((n, b) => n + (b.events?.length ?? 0), 0);
  const sevCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const b of batches) for (const e of b.events ?? []) sevCounts[e.severity] += 1;
  const hostSet = new Set(batches.map((b) => b.host_id));

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
          description="尚未收到任何 guard 上报。请在扫描页下发 guard 任务，部署常驻防护进程后事件会出现在这里。"
        >
          <Button render={<Link href="/scans" />}>前往下发 guard 任务</Button>
        </EmptyState>
      ) : (
        <div className="flex flex-col gap-6">
          {/* KPI 概览条 */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              icon={ShieldAlert}
              label="防护事件"
              value={allEvents}
              sublabel={`${batches.length} 个批次`}
            />
            <Stat icon={ShieldAlert} label="严重" value={sevCounts.critical} accent="text-red-600" sublabel="critical" />
            <Stat icon={TriangleAlert} label="高危" value={sevCounts.high} accent="text-orange-500" sublabel="high" />
            <Stat icon={Server} label="涉及主机" value={hostSet.size} sublabel="去重主机" />
          </div>

          <div className="flex flex-col gap-4">
            {batches.map((batch) => (
              <BatchCard key={batch.batch_id} batch={batch} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
