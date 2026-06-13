import { ChevronRight, Server, Bug, Network } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { AlertStatusBadge } from "@/components/alert-status-badge";
import { CopyableId } from "@/components/copy-button";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { FusionApiError, getAlert } from "@/lib/api";
import type { Alert } from "@/lib/contracts";
import { fmtTimestampFull } from "@/lib/format";

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
    if (err instanceof FusionApiError && err.status === 404) notFound();
    throw err;
  }

  const status = alert.status ?? "open";
  const assetIds = alert.related_asset_ids ?? [];
  const vulnIds = alert.related_vuln_ids ?? [];
  const flowIds = alert.related_flow_ids ?? [];

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
            <Badge variant="secondary" className="tabular-nums">
              风险分 {alert.score.toFixed(0)}
            </Badge>
          </div>
          <CardTitle className="text-lg leading-snug">{alert.title}</CardTitle>
          <CardDescription className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-xs">
            <span>创建于 {fmtTimestampFull(alert.created_at)}</span>
            {alert.updated_at && <span>更新于 {fmtTimestampFull(alert.updated_at)}</span>}
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

      {(assetIds.length > 0 || vulnIds.length > 0 || flowIds.length > 0) && (
        <div className="grid gap-4">
          <RelatedIds icon={Server} label="关联资产" ids={assetIds} />
          <RelatedIds icon={Bug} label="关联漏洞" ids={vulnIds} />
          <RelatedIds icon={Network} label="关联流量" ids={flowIds} />
        </div>
      )}
    </div>
  );
}
