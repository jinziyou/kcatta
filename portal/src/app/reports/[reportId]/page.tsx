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
import { FusionApiError, getAssetReport } from "@/lib/api";
import type { Asset, AssetKind, AssetReport } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const KIND_LABEL: Record<AssetKind, string> = {
  package: "Packages",
  service: "Services",
  port: "Ports",
  account: "Accounts",
  credential: "Credentials",
};

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function assetsByKind(assets: Asset[]): Record<AssetKind, Asset[]> {
  const groups: Record<AssetKind, Asset[]> = {
    package: [],
    service: [],
    port: [],
    account: [],
    credential: [],
  };
  for (const asset of assets) {
    const kind = asset.kind;
    if (kind) groups[kind].push(asset);
  }
  return groups;
}

function AssetRow({ asset }: { asset: Asset }) {
  switch (asset.kind) {
    case "package":
      return (
        <li className="font-mono text-xs">
          {asset.name} {asset.version}
          {asset.source ? ` (${asset.source})` : ""}
        </li>
      );
    case "service":
      return (
        <li className="font-mono text-xs">
          {asset.name} — {asset.status}
        </li>
      );
    case "port":
      return (
        <li className="font-mono text-xs">
          {asset.proto}/{asset.port} on {asset.listen_addr}
        </li>
      );
    case "account":
      return (
        <li className="font-mono text-xs">
          {asset.username}
          {asset.uid != null ? ` (uid ${asset.uid})` : ""}
        </li>
      );
    case "credential":
      return (
        <li className="font-mono text-xs">
          {asset.credential_kind} {asset.fingerprint.slice(0, 16)}…
        </li>
      );
    default:
      return null;
  }
}

function ReportDetail({ report }: { report: AssetReport }) {
  const assets = report.assets ?? [];
  const groups = assetsByKind(assets);
  const vulns = report.vulnerabilities ?? [];

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            <span className="font-mono">{report.host.hostname}</span>
            <Badge variant="secondary">{report.host.os}</Badge>
          </CardTitle>
          <CardDescription className="flex flex-col gap-1 font-mono text-xs">
            <span>report {report.report_id}</span>
            <span>host {report.host.host_id}</span>
            <span>collected {formatTimestamp(report.collected_at)}</span>
            <span>scanner v{report.scanner_version}</span>
          </CardDescription>
        </CardHeader>
        <CardContent className="text-muted-foreground flex flex-col gap-1 text-sm">
          {report.host.ip_addrs && report.host.ip_addrs.length > 0 && (
            <span>IPs: {report.host.ip_addrs.join(", ")}</span>
          )}
          {report.host.kernel && <span>Kernel: {report.host.kernel}</span>}
          {report.host.arch && <span>Arch: {report.host.arch}</span>}
        </CardContent>
      </Card>

      {(Object.keys(groups) as AssetKind[]).map((kind) =>
        groups[kind].length > 0 ? (
          <Card key={kind}>
            <CardHeader>
              <CardTitle className="text-base">
                {KIND_LABEL[kind]} ({groups[kind].length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="flex flex-col gap-1">
                {groups[kind].map((asset) => (
                  <AssetRow key={asset.asset_id} asset={asset} />
                ))}
              </ul>
            </CardContent>
          </Card>
        ) : null,
      )}

      {vulns.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Scanner findings ({vulns.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="flex flex-col gap-2">
              {vulns.map((v) => (
                <li key={`${v.vuln_id}:${v.affected_asset_id}`} className="font-mono text-xs">
                  <Badge variant="outline">{v.severity}</Badge> {v.vuln_id} → {v.affected_asset_id}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default async function ReportPage({
  params,
}: {
  params: Promise<{ reportId: string }>;
}) {
  const { reportId } = await params;

  let report: AssetReport;
  try {
    report = await getAssetReport(reportId);
  } catch (err) {
    if (err instanceof FusionApiError && err.status === 404) {
      notFound();
    }
    throw err;
  }

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <Link
        href="/"
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
      >
        ← Asset reports
      </Link>
      <ReportDetail report={report} />
    </div>
  );
}
