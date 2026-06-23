import { Bug, ChevronRight, Network, Server, Target } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { AlertStatusBadge } from "@/components/alert-status-badge";
import { AlertTriageForm } from "@/components/alert-triage-form";
import { CopyableId } from "@/components/copy-button";
import { SeverityBadge } from "@/components/severity-badge";
import { Stat } from "@/components/stat";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { AnalyzerApiError, getAlert } from "@/lib/api";
import type { Alert } from "@/lib/contracts";
import { fmtTimestampFull } from "@/lib/format";
import { SEVERITY_ACCENT } from "@/lib/meta";

export const dynamic = "force-dynamic";

/** A labeled section listing related entity ids as monospace badges. */
function RelatedIds({
  icon: Icon,
  label,
  ids,
}: {
  icon: LucideIcon;
  label: string;
  ids: string[];
}) {
  if (ids.length === 0) return null;
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icon className="text-muted-foreground size-4" />
          {label}
          <span className="text-muted-foreground tabular-nums">{ids.length}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-1.5">
          {ids.map((id) => (
            <Badge key={id} variant="outline" className="font-mono text-xs font-normal">
              {id}
            </Badge>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export default async function AlertDetailPage({
  params,
}: {
  params: Promise<{ alertId: string }>;
}) {
  const { alertId } = await params;

  let alert: Alert;
  try {
    alert = await getAlert(alertId);
  } catch (err) {
    if (err instanceof AnalyzerApiError && err.status === 404) notFound();
    throw err;
  }

  const status = alert.status ?? "open";
  const assetIds = alert.related_asset_ids ?? [];
  const vulnIds = alert.related_vuln_ids ?? [];
  const traceIds = alert.related_trace_ids ?? [];
  const occurrences = alert.occurrence_count ?? 1;
  // Triage keys on the content-derived alert_key; fall back to the occurrence id
  // for alerts persisted before alert_key existed (the API accepts either).
  const triageKey = alert.alert_key ?? alert.alert_id;

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-8">
      <nav className="text-muted-foreground mb-5 flex items-center gap-1 text-sm">
        <Link href="/alerts" className="hover:text-foreground">
          关联告警
        </Link>
        <ChevronRight className="size-3.5" />
        <span className="text-foreground">告警详情</span>
      </nav>

      <Card className="mb-6">
        <CardHeader>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <AlertStatusBadge status={status} />
            {alert.suppressed && (
              <Badge variant="outline" className="text-xs">
                已抑制
              </Badge>
            )}
            {occurrences > 1 && (
              <Badge variant="secondary" className="text-xs tabular-nums">
                命中 {occurrences} 次
              </Badge>
            )}
            {alert.assignee && (
              <Badge variant="outline" className="text-xs">
                处置人 {alert.assignee}
              </Badge>
            )}
          </div>
          <CardTitle className="text-lg leading-snug">{alert.title}</CardTitle>
          <CardDescription className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-xs">
            <span>创建于 {fmtTimestampFull(alert.created_at)}</span>
            {alert.last_seen && <span>最近命中 {fmtTimestampFull(alert.last_seen)}</span>}
            {alert.updated_at && <span>处置于 {fmtTimestampFull(alert.updated_at)}</span>}
            <CopyableId value={alert.alert_id} />
          </CardDescription>
        </CardHeader>
        {alert.description && (
          <CardContent>
            <Separator className="mb-4" />
            <p className="text-sm leading-relaxed whitespace-pre-line">{alert.description}</p>
          </CardContent>
        )}
      </Card>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="text-sm">处置</CardTitle>
          <CardDescription>更新此告警的状态、处置人、备注与抑制。</CardDescription>
        </CardHeader>
        <CardContent>
          <AlertTriageForm
            alertKey={triageKey}
            initialStatus={status}
            initialAssignee={alert.assignee ?? ""}
            initialNote={alert.note ?? ""}
            initialSuppressed={alert.suppressed ?? false}
          />
        </CardContent>
      </Card>

      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat
          label="风险分"
          value={alert.score.toFixed(0)}
          icon={Target}
          accent={SEVERITY_ACCENT[alert.severity]}
        />
        <Stat label="关联资产" value={assetIds.length} icon={Server} />
        <Stat label="关联漏洞" value={vulnIds.length} icon={Bug} />
        <Stat label="关联流量" value={traceIds.length} icon={Network} />
      </div>

      {(assetIds.length > 0 || vulnIds.length > 0 || traceIds.length > 0) && (
        <div className="grid gap-4">
          <RelatedIds icon={Server} label="关联资产" ids={assetIds} />
          <RelatedIds icon={Bug} label="关联漏洞" ids={vulnIds} />
          <RelatedIds icon={Network} label="关联流量" ids={traceIds} />
        </div>
      )}
    </div>
  );
}
