import { Bug, Server } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState, ErrorState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FusionApiError, listVulnerabilities } from "@/lib/api";
import type { DetectionResult, Severity, Vulnerability } from "@/lib/contracts";
import { fmtTimestamp } from "@/lib/format";
import { SEVERITY_META, SEVERITY_ORDER, SEVERITY_RANK } from "@/lib/meta";

export const dynamic = "force-dynamic";

type SourceFilter = "osv" | "clamav";

const SOURCE_FILTERS: SourceFilter[] = ["osv", "clamav"];

const SOURCE_LABEL: Record<SourceFilter, string> = {
  osv: "OSV/CVE",
  clamav: "ClamAV",
};

/** Solid source-badge classes (theme-safe text on a colored fill). */
const SOURCE_BADGE: Record<SourceFilter, string> = {
  osv: "bg-blue-600 text-white border-transparent",
  clamav: "bg-purple-600 text-white border-transparent",
};

function vulnsOf(result: DetectionResult): Vulnerability[] {
  return result.vulnerabilities ?? [];
}

/** Highest-severity / highest-cvss first within a host card. */
function bySeverity(a: Vulnerability, b: Vulnerability): number {
  const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (rank !== 0) return rank;
  return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
}

function parseMinSeverity(value: string | string[] | undefined): Severity | null {
  const v = typeof value === "string" ? value : undefined;
  return v && SEVERITY_ORDER.includes(v as Severity) ? (v as Severity) : null;
}

function parseSource(value: string | string[] | undefined): SourceFilter | null {
  const v = typeof value === "string" ? value : undefined;
  return v === "osv" || v === "clamav" ? v : null;
}

function buildHref(severity: Severity | null, source: SourceFilter | null): string {
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (source) params.set("source", source);
  const q = params.toString();
  return q ? `/vulnerabilities?${q}` : "/vulnerabilities";
}

/** A Badge wrapped in a Link; active uses a solid/colored fill, otherwise outline. */
function FilterChip({
  href,
  label,
  active,
  activeClassName,
}: {
  href: string;
  label: string;
  active: boolean;
  activeClassName?: string;
}) {
  return (
    <Badge
      variant={active ? "default" : "outline"}
      className={active ? activeClassName : undefined}
      render={<Link href={href} />}
    >
      {label}
    </Badge>
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
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground w-16 text-xs">最小严重度</span>
        <FilterChip href={buildHref(null, source)} label="全部" active={severity === null} />
        {SEVERITY_ORDER.map((s) => (
          <FilterChip
            key={s}
            href={buildHref(s, source)}
            label={SEVERITY_META[s].label}
            active={severity === s}
            activeClassName={SEVERITY_META[s].badge}
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground w-16 text-xs">来源</span>
        <FilterChip href={buildHref(severity, null)} label="全部" active={source === null} />
        {SOURCE_FILTERS.map((s) => (
          <FilterChip
            key={s}
            href={buildHref(severity, s)}
            label={SOURCE_LABEL[s]}
            active={source === s}
            activeClassName={SOURCE_BADGE[s]}
          />
        ))}
      </div>
    </div>
  );
}

function SourceBadge({ source }: { source: string }) {
  if (source === "osv" || source === "clamav") {
    return <Badge className={SOURCE_BADGE[source]}>{SOURCE_LABEL[source]}</Badge>;
  }
  return <Badge variant="outline">{source}</Badge>;
}

function VulnerabilityRow({ vuln }: { vuln: Vulnerability }) {
  return (
    <li className="flex flex-col gap-1 border-t py-2.5 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={vuln.severity} />
        <SourceBadge source={vuln.source} />
        <span className="font-mono text-sm font-medium">{vuln.vuln_id}</span>
        {vuln.cvss_score != null && (
          <Badge variant="secondary">CVSS {vuln.cvss_score.toFixed(1)}</Badge>
        )}
        <span className="text-muted-foreground font-mono text-xs">{vuln.affected_asset_id}</span>
      </div>
      {vuln.evidence && (
        <span className="text-muted-foreground text-xs">{vuln.evidence}</span>
      )}
    </li>
  );
}

function ResultCard({ result }: { result: DetectionResult }) {
  const vulns = [...vulnsOf(result)].sort(bySeverity);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          <span className="truncate font-mono">{result.host_id}</span>
          {result.ecosystem && <Badge variant="secondary">{result.ecosystem}</Badge>}
          <span className="text-muted-foreground ml-auto font-mono text-xs font-normal">
            {fmtTimestamp(result.collected_at)}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col">
          {vulns.map((vuln) => (
            <VulnerabilityRow
              key={`${vuln.vuln_id}:${vuln.affected_asset_id}`}
              vuln={vuln}
            />
          ))}
        </ul>
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

function applySource(results: DetectionResult[], source: SourceFilter | null): DetectionResult[] {
  if (source === null) return results;
  return results
    .map((r) => ({
      ...r,
      vulnerabilities: vulnsOf(r).filter((v) => v.source === source),
    }))
    .filter((r) => vulnsOf(r).length > 0);
}

export default async function VulnerabilitiesPage({
  searchParams,
}: {
  searchParams: Promise<{ severity?: string | string[]; source?: string | string[] }>;
}) {
  const sp = await searchParams;
  const activeSeverity = parseMinSeverity(sp.severity);
  const activeSource = parseSource(sp.source);

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
  const filtered = applySource(applyMinSeverity(withFindings, activeSeverity), activeSource);

  // Severity tallies + total findings drawn from the filtered view.
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let total = 0;
  for (const r of filtered) {
    for (const v of vulnsOf(r)) {
      counts[v.severity] += 1;
      total += 1;
    }
  }

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="漏洞发现"
        description="对入库资产报告的检测结果：OSV/CVE 软件漏洞匹配与 ClamAV 恶意文件命中，按主机分组、最新在前。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : withFindings.length === 0 ? (
        <EmptyState
          icon={Bug}
          title="暂无漏洞发现"
          description="入库资产报告后会自动检测：加载本地漏洞库后进行 OSV/CVE 匹配，并解析扫描报告中的 ClamAV 命中。"
        />
      ) : (
        <div className="flex flex-col gap-6">
          <FilterBar severity={activeSeverity} source={activeSource} />

          {filtered.length === 0 ? (
            <EmptyState
              icon={Bug}
              title="没有符合当前过滤条件的发现"
              description="尝试调低最小严重度，或切换来源筛选。"
            />
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">
                  <Bug className="size-3.5" />
                  {total} 项发现
                </Badge>
                <Badge variant="outline">
                  <Server className="size-3.5" />
                  {filtered.length} 台主机
                </Badge>
                {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
                  <SeverityBadge key={s} severity={s} count={counts[s]} />
                ))}
              </div>

              <div className="grid gap-4">
                {filtered.map((result) => (
                  <ResultCard key={result.report_id} result={result} />
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
