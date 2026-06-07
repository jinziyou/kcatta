import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FormApiError, listAssetReports } from "@/lib/api";
import type { AssetKind, AssetReport } from "@/lib/contracts";

export const dynamic = "force-dynamic";

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function countByKind(report: AssetReport): Record<AssetKind, number> {
  const acc: Record<AssetKind, number> = {
    package: 0,
    service: 0,
    port: 0,
    account: 0,
    credential: 0,
  };
  for (const asset of report.assets ?? []) {
    const kind = asset.kind;
    if (kind) acc[kind] += 1;
  }
  return acc;
}

const KIND_LABEL: Record<AssetKind, string> = {
  package: "Packages",
  service: "Services",
  port: "Ports",
  account: "Accounts",
  credential: "Credentials",
};

function ReportCard({ report }: { report: AssetReport }) {
  const counts = countByKind(report);
  const totalAssets = (report.assets ?? []).length;
  return (
    <Link href={`/reports/${encodeURIComponent(report.report_id)}`}>
      <Card className="transition-colors hover:bg-muted/30">
        <CardHeader>
          <CardTitle className="flex items-center justify-between gap-3">
            <span className="truncate font-mono text-sm">{report.host.hostname}</span>
            <Badge variant="secondary">{report.host.os}</Badge>
          </CardTitle>
          <CardDescription className="flex flex-col gap-1">
            <span>
              <span className="text-muted-foreground">collected </span>
              <span className="font-mono">{formatTimestamp(report.collected_at)}</span>
            </span>
            <span className="text-muted-foreground/80 truncate font-mono text-xs">
              {report.report_id}
            </span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            <Badge variant="outline">{totalAssets} assets</Badge>
            {(Object.keys(counts) as AssetKind[])
              .filter((k) => counts[k] > 0)
              .map((kind) => (
                <Badge key={kind} variant="secondary">
                  {KIND_LABEL[kind]}: {counts[kind]}
                </Badge>
              ))}
            {(report.vulnerabilities ?? []).length > 0 && (
              <Badge variant="destructive">{(report.vulnerabilities ?? []).length} vulns</Badge>
            )}
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
        <CardTitle>No reports yet</CardTitle>
        <CardDescription>
          Scanner has not uploaded anything. Run the agent against this form instance to populate
          the dashboard.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="bg-muted overflow-x-auto rounded-md p-3 font-mono text-xs">
          cargo run -p fusion-host-cli | curl -X POST --data-binary @- \
            http://127.0.0.1:8000/ingest/asset-report
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

export default async function Home() {
  let reports: AssetReport[] = [];
  let error: FormApiError | null = null;
  try {
    reports = await listAssetReports(50);
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <header className="mb-8 flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Asset reports</h1>
        <p className="text-muted-foreground text-sm">
          Latest host scans uploaded to form, newest first.
        </p>
      </header>

      {error ? (
        <ErrorState error={error} />
      ) : reports.length === 0 ? (
        <EmptyState />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {reports.map((report) => (
            <ReportCard key={report.report_id} report={report} />
          ))}
        </div>
      )}
    </div>
  );
}
