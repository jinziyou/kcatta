import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FormApiError, listVulnerabilities } from "@/lib/api";
import type { DetectionResult, Severity, Vulnerability } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

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

function bySeverity(a: Vulnerability, b: Vulnerability): number {
  const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (rank !== 0) return rank;
  return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge className={SEVERITY_CLASS[severity]}>{severity}</Badge>;
}

function Summary({ results }: { results: DetectionResult[] }) {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let total = 0;
  for (const result of results) {
    for (const vuln of result.vulnerabilities) {
      counts[vuln.severity] += 1;
      total += 1;
    }
  }
  return (
    <div className="mb-6 flex flex-wrap items-center gap-2">
      <Badge variant="outline">{total} findings</Badge>
      <Badge variant="outline">{results.length} hosts</Badge>
      {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
        <Badge key={s} className={SEVERITY_CLASS[s]}>
          {s}: {counts[s]}
        </Badge>
      ))}
    </div>
  );
}

function VulnerabilityRow({ vuln }: { vuln: Vulnerability }) {
  return (
    <li className="flex flex-col gap-1 border-t py-2 first:border-t-0">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={vuln.severity} />
        <span className="font-mono text-sm font-medium">{vuln.vuln_id}</span>
        {vuln.cvss_score !== null && (
          <Badge variant="secondary">CVSS {vuln.cvss_score.toFixed(1)}</Badge>
        )}
        <span className="text-muted-foreground/80 font-mono text-xs">{vuln.affected_asset_id}</span>
      </div>
      {vuln.evidence && (
        <span className="text-muted-foreground text-xs">{vuln.evidence}</span>
      )}
    </li>
  );
}

function ResultCard({ result }: { result: DetectionResult }) {
  const vulns = [...result.vulnerabilities].sort(bySeverity);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3">
          <span className="truncate font-mono text-sm">{result.host_id}</span>
          <Badge variant="secondary">{result.ecosystem}</Badge>
        </CardTitle>
        <CardDescription className="flex flex-col gap-1">
          <span>
            <span className="text-muted-foreground">collected </span>
            <span className="font-mono">{formatTimestamp(result.collected_at)}</span>
          </span>
          <span className="text-muted-foreground/80 truncate font-mono text-xs">
            {result.report_id}
          </span>
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col">
          {vulns.map((vuln) => (
            <VulnerabilityRow key={`${vuln.vuln_id}:${vuln.affected_asset_id}`} vuln={vuln} />
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function EmptyState() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>No vulnerabilities detected</CardTitle>
        <CardDescription>
          Detection runs automatically on ingest once an OSV store is loaded. Sync a database and
          re-ingest a report to populate this view.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="bg-muted overflow-x-auto rounded-md p-3 font-mono text-xs">
          form-osv-sync --ecosystem Debian{"\n"}cargo run -p scanner-cli | curl -X POST
          --data-binary @- http://127.0.0.1:8000/ingest/asset-report
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

export default async function Vulnerabilities() {
  let results: DetectionResult[] = [];
  let error: FormApiError | null = null;
  try {
    results = await listVulnerabilities(50);
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  const withFindings = results.filter((r) => r.vulnerabilities.length > 0);

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <header className="mb-8 flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Vulnerabilities</h1>
        <p className="text-muted-foreground text-sm">
          Findings from package inventory matched against OSV advisories, newest first.
        </p>
      </header>

      {error ? (
        <ErrorState error={error} />
      ) : withFindings.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <Summary results={withFindings} />
          <div className="grid gap-4">
            {withFindings.map((result) => (
              <ResultCard key={result.report_id} result={result} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
