import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FusionApiError, listVulnerabilities } from "@/lib/api";
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

type SourceFilter = "osv" | "clamav";

const SOURCE_LABEL: Record<SourceFilter, string> = {
  osv: "OSV / CVE",
  clamav: "ClamAV",
};

const SOURCE_CLASS: Record<SourceFilter, string> = {
  osv: "bg-blue-600 text-white",
  clamav: "bg-purple-600 text-white",
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

function vulnsOf(result: DetectionResult): Vulnerability[] {
  return result.vulnerabilities ?? [];
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
    for (const vuln of vulnsOf(result)) {
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

function parseMinSeverity(value: string | undefined): Severity | null {
  return value && SEVERITY_ORDER.includes(value as Severity) ? (value as Severity) : null;
}

function parseSource(value: string | undefined): SourceFilter | null {
  return value === "osv" || value === "clamav" ? value : null;
}

function buildFilterHref(severity: Severity | null, source: SourceFilter | null): string {
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (source) params.set("source", source);
  const q = params.toString();
  return q ? `/vulnerabilities?${q}` : "/vulnerabilities";
}

function FilterChip({
  href,
  label,
  active,
  className,
}: {
  href: string;
  label: string;
  active: boolean;
  className?: string;
}) {
  return (
    <Link href={href}>
      <Badge variant={active ? "default" : "outline"} className={active ? className : undefined}>
        {label}
      </Badge>
    </Link>
  );
}

function FilterBar({
  severity,
  source,
}: {
  severity: Severity | null;
  source: SourceFilter | null;
}) {
  return (
    <div className="mb-4 flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground text-xs">min severity</span>
        <FilterChip
          href={buildFilterHref(null, source)}
          label="All"
          active={severity === null}
        />
        {SEVERITY_ORDER.map((s) => (
          <FilterChip
            key={s}
            href={buildFilterHref(s, source)}
            label={s}
            active={severity === s}
            className={SEVERITY_CLASS[s]}
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground text-xs">source</span>
        <FilterChip
          href={buildFilterHref(severity, null)}
          label="All"
          active={source === null}
        />
        {(Object.keys(SOURCE_LABEL) as SourceFilter[]).map((s) => (
          <FilterChip
            key={s}
            href={buildFilterHref(severity, s)}
            label={SOURCE_LABEL[s]}
            active={source === s}
            className={SOURCE_CLASS[s]}
          />
        ))}
      </div>
    </div>
  );
}

function SourceBadge({ source }: { source: string }) {
  if (source === "osv" || source === "clamav") {
    return <Badge className={SOURCE_CLASS[source]}>{SOURCE_LABEL[source]}</Badge>;
  }
  return <Badge variant="outline">{source}</Badge>;
}

function VulnerabilityRow({ vuln }: { vuln: Vulnerability }) {
  return (
    <li className="flex flex-col gap-1 border-t py-2 first:border-t-0">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={vuln.severity} />
        <SourceBadge source={vuln.source} />
        <span className="font-mono text-sm font-medium">{vuln.vuln_id}</span>
        {vuln.cvss_score != null && (
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
  const vulns = [...vulnsOf(result)].sort(bySeverity);
  const ecosystemLabel = result.ecosystem || "—";
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3">
          <span className="truncate font-mono text-sm">{result.host_id}</span>
          <Badge variant="secondary">{ecosystemLabel}</Badge>
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
        <CardTitle>No findings yet</CardTitle>
        <CardDescription>
          Detection runs automatically on ingest: OSV/CVE matching when a local advisory store is
          loaded, plus ClamAV malware hits from scanner reports.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="bg-muted overflow-x-auto rounded-md p-3 font-mono text-xs">
          fusion-osv-sync --ecosystem Debian{"\n"}cargo run -p agent-runtime -- host -r / | curl -X POST
          --data-binary @- http://127.0.0.1:8000/ingest/asset-report
        </pre>
      </CardContent>
    </Card>
  );
}

function ErrorState({ error }: { error: FusionApiError }) {
  return (
    <Card className="border-destructive/40">
      <CardHeader>
        <CardTitle className="text-destructive">Cannot reach fusion API</CardTitle>
        <CardDescription>{error.message}</CardDescription>
      </CardHeader>
      <CardContent className="text-muted-foreground text-sm">
        Make sure <span className="font-mono">fusion-api</span> is running and that
        <span className="font-mono"> NEXT_PUBLIC_FUSION_BASE_URL</span> points at it.
      </CardContent>
    </Card>
  );
}

function applyMinSeverity(results: DetectionResult[], min: Severity | null): DetectionResult[] {
  if (min === null) return results;
  const threshold = SEVERITY_RANK[min];
  return results
    .map((r) => ({
      ...r,
      vulnerabilities: vulnsOf(r).filter((v) => SEVERITY_RANK[v.severity] >= threshold),
    }))
    .filter((r) => vulnsOf(r).length > 0);
}

function applySourceFilter(
  results: DetectionResult[],
  source: SourceFilter | null,
): DetectionResult[] {
  if (source === null) return results;
  return results
    .map((r) => ({
      ...r,
      vulnerabilities: vulnsOf(r).filter((v) => v.source === source),
    }))
    .filter((r) => vulnsOf(r).length > 0);
}

export default async function Vulnerabilities({
  searchParams,
}: {
  searchParams: Promise<{ severity?: string | string[]; source?: string | string[] }>;
}) {
  const sp = await searchParams;
  const severityParam = typeof sp.severity === "string" ? sp.severity : undefined;
  const sourceParam = typeof sp.source === "string" ? sp.source : undefined;
  const activeSeverity = parseMinSeverity(severityParam);
  const activeSource = parseSource(sourceParam);

  let results: DetectionResult[] = [];
  let error: FusionApiError | null = null;
  try {
    results = await listVulnerabilities(50);
  } catch (err) {
    error =
      err instanceof FusionApiError
        ? err
        : new FusionApiError(err instanceof Error ? err.message : String(err));
  }

  const withFindings = results.filter((r) => vulnsOf(r).length > 0);
  const filtered = applySourceFilter(
    applyMinSeverity(withFindings, activeSeverity),
    activeSource,
  );

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <header className="mb-8 flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <p className="text-muted-foreground text-sm">
          OSV/CVE matches and ClamAV malware hits from ingested reports, newest first.
        </p>
      </header>

      {error ? (
        <ErrorState error={error} />
      ) : withFindings.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <FilterBar severity={activeSeverity} source={activeSource} />
          {filtered.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              No findings match the current filters.
            </p>
          ) : (
            <>
              <Summary results={filtered} />
              <div className="grid gap-4">
                {filtered.map((result) => (
                  <ResultCard key={result.report_id} result={result} />
                ))}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
