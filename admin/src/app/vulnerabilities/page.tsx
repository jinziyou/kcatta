import { Box, Bug, Container, Server, ShieldAlert, TriangleAlert } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";

import { FilterChip } from "@/components/filter-chip";
import { CoverageMatrix } from "@/components/coverage-matrix";
import { PageHeader } from "@/components/page-header";
import { PageNav } from "@/components/page-nav";
import { SeverityBadge } from "@/components/severity-badge";
import { Stat } from "@/components/stat";
import { EmptyState, ErrorState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FormApiError, listVulnerabilitiesCursor } from "@/lib/api";
import type { DetectionResult, Severity, Vulnerability } from "@/lib/contracts";
import {
  DETECTION_STATUS_LABEL,
  detectionCoverage,
  detectionReasonLabel,
  detectionRecordComplete,
} from "@/lib/detection";
import { fmtTimestamp } from "@/lib/format";
import { SEVERITY_META, SEVERITY_ORDER, SEVERITY_RANK } from "@/lib/meta";
import {
  cursorNavigation,
  parseCursor,
  parseCursorTrail,
  parsePage,
} from "@/lib/pagination";

export const dynamic = "force-dynamic";

type SourceFilter =
  | "osv"
  | "debian_tracker"
  | "defender"
  | "mdvm"
  | "malware"
  | "posture"
  | "secret";

const SOURCE_FILTERS: SourceFilter[] = [
  "osv",
  "debian_tracker",
  "defender",
  "mdvm",
  "malware",
  "posture",
  "secret",
];

const SOURCE_LABEL: Record<SourceFilter, string> = {
  osv: "OSV/CVE",
  debian_tracker: "Debian Tracker/CVE",
  defender: "Microsoft Defender",
  mdvm: "Microsoft Defender VM",
  malware: "内置查毒",
  posture: "安全基线",
  secret: "密钥泄露（按需启用）",
};

/** Active source-filter chip classes (low-tint team fill, archive palette). */
const SOURCE_BADGE: Record<SourceFilter, string> = {
  osv: "bg-team-blue/10 text-team-blue border-team-blue/30",
  debian_tracker: "border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-400",
  defender: "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400",
  mdvm: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-400",
  malware: "bg-team-purple/10 text-team-purple border-team-purple/30",
  posture: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
  secret: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400",
};

/** Vulnerability `source` values that the 内置查毒 filter matches（含遗留 `clamav`）。 */
const MALWARE_SOURCES = new Set(["kcatta-malware", "clamav"]);
const DEFENDER_SOURCES = new Set(["microsoft-defender", "microsoft-defender-event"]);
const MDVM_SOURCE = "microsoft-defender-vulnerability-management";

// DetectionResult is a variable-cardinality record: a single host can contain
// thousands of findings. Record pagination alone therefore does not bound the
// rendered response. Keep the list page to a predictable 10 x 20 preview while
// retaining complete counts and a link to the full report.
const VULNERABILITY_RESULT_PAGE_SIZE = 10;
const FINDING_PREVIEW_LIMIT = 20;

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
  return v === "osv" ||
    v === "debian_tracker" ||
    v === "defender" ||
    v === "mdvm" ||
    v === "malware" ||
    v === "posture" ||
    v === "secret"
    ? v
    : null;
}

function buildHref(severity: Severity | null, source: SourceFilter | null): string {
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (source) params.set("source", source);
  const q = params.toString();
  return q ? `/vulnerabilities?${q}` : "/vulnerabilities";
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
  if (source === "osv") {
    return <Badge className={SOURCE_BADGE.osv}>{SOURCE_LABEL.osv}</Badge>;
  }
  if (source === "debian-security-tracker") {
    return (
      <Badge className={SOURCE_BADGE.debian_tracker}>{SOURCE_LABEL.debian_tracker}</Badge>
    );
  }
  if (MALWARE_SOURCES.has(source)) {
    return <Badge className={SOURCE_BADGE.malware}>{SOURCE_LABEL.malware}</Badge>;
  }
  if (DEFENDER_SOURCES.has(source)) {
    return <Badge className={SOURCE_BADGE.defender}>{SOURCE_LABEL.defender}</Badge>;
  }
  if (source === MDVM_SOURCE) {
    return <Badge className={SOURCE_BADGE.mdvm}>{SOURCE_LABEL.mdvm}</Badge>;
  }
  if (source === "posture" || source === "secret") {
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
      {vuln.references && vuln.references.length > 0 && (
        <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
          <span className="text-muted-foreground">参考</span>
          {vuln.references.map((reference) =>
            /^https?:\/\//i.test(reference) ? (
              <a
                key={reference}
                href={reference}
                target="_blank"
                rel="noreferrer"
                className="max-w-full break-all text-primary hover:underline"
              >
                {reference}
              </a>
            ) : (
              <span key={reference} className="break-all font-mono">
                {reference}
              </span>
            ),
          )}
        </div>
      )}
    </li>
  );
}

/** Friendly label + icon for a nested (image/container) attribution id. */
function nestedLabel(id: string): string {
  if (id.startsWith("img-")) return `镜像 ${id}`;
  if (id.startsWith("ctr-")) return `容器 ${id}`;
  return id;
}

function nestedIcon(id: string): LucideIcon {
  return id.startsWith("ctr-") ? Container : Box;
}

/** A labeled list of findings (a host bucket or a per-image/container bucket). */
function GroupBlock({
  label,
  icon: Icon,
  vulns,
}: {
  label: string | null;
  icon: LucideIcon;
  vulns: Vulnerability[];
}) {
  return (
    <div>
      {label && (
        <div className="text-muted-foreground mb-1.5 flex items-center gap-1.5 text-xs">
          <Icon className="size-3.5" />
          <span className="font-mono">{label}</span>
          <Badge variant="outline" className="text-xs">
            {vulns.length}
          </Badge>
        </div>
      )}
      <ul className="flex flex-col">
        {vulns.map((vuln) => (
          <VulnerabilityRow
            key={`${vuln.source}:${vuln.vuln_id}:${vuln.affected_asset_id}:${vuln.parent_asset_id ?? ""}:${vuln.evidence ?? ""}`}
            vuln={vuln}
          />
        ))}
      </ul>
    </div>
  );
}

function ResultCard({ result }: { result: DetectionResult }) {
  const allVulns = [...vulnsOf(result)].sort(bySeverity);
  const vulns = allVulns.slice(0, FINDING_PREVIEW_LIMIT);
  const hiddenFindingCount = allVulns.length - vulns.length;
  const coverage = detectionCoverage(result);
  const complete = detectionRecordComplete(result);
  // Group findings by their owning image/container (parent_asset_id); host-level
  // findings (no parent) form a separate bucket. Insertion order follows the
  // severity sort, so each bucket stays worst-first.
  const host: Vulnerability[] = [];
  const byParent = new Map<string, Vulnerability[]>();
  for (const vuln of vulns) {
    if (vuln.parent_asset_id) {
      const arr = byParent.get(vuln.parent_asset_id) ?? [];
      arr.push(vuln);
      byParent.set(vuln.parent_asset_id, arr);
    } else {
      host.push(vuln);
    }
  }
  const nestedParentCount = new Set(
    allVulns.flatMap((vuln) => (vuln.parent_asset_id ? [vuln.parent_asset_id] : [])),
  ).size;
  const hasNested = nestedParentCount > 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          <span className="truncate font-mono">{result.host_id}</span>
          {result.ecosystem && <Badge variant="secondary">{result.ecosystem}</Badge>}
          <Badge variant={complete ? "secondary" : "outline"}>
            {DETECTION_STATUS_LABEL[coverage.status]}
          </Badge>
          {coverage.truncated && <Badge variant="destructive">发现已截断</Badge>}
          {hasNested && (
            <Badge variant="outline" className="text-xs">
              {nestedParentCount} 个镜像/容器
            </Badge>
          )}
          <span className="text-muted-foreground ml-auto font-mono text-xs font-normal">
            {fmtTimestamp(result.collected_at)}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Link
          href={`/reports/${encodeURIComponent(result.report_id)}`}
          className="text-muted-foreground w-fit font-mono text-xs hover:text-foreground hover:underline"
        >
          查看源报告 {result.report_id}
        </Link>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <Badge variant="outline">已纳入 OSV 匹配 {coverage.scannedPackages}</Badge>
          {coverage.unresolvedPackages > 0 && (
            <Badge variant="outline">
              生态无法解析、未纳入 OSV 匹配 {coverage.unresolvedPackages}
            </Badge>
          )}
          {coverage.uncoveredPackages > 0 && (
            <Badge variant="outline">
              OSV 未覆盖（未同步或不支持）{coverage.uncoveredPackages}
            </Badge>
          )}
          {coverage.reason && (
            <Badge variant="outline">原因 {detectionReasonLabel(coverage.reason)}</Badge>
          )}
          {coverage.truncated && (
            <Badge variant="destructive">
              截断原因 {detectionReasonLabel(coverage.truncationReason ?? "limit_reached")}
            </Badge>
          )}
        </div>
        <details className="group">
          <summary className="text-muted-foreground cursor-pointer text-xs hover:text-foreground">
            查看检测器 / 生态覆盖矩阵（{result.coverage?.length ?? 0} 项）
          </summary>
          <div className="mt-3">
            <CoverageMatrix rows={result.coverage ?? []} />
          </div>
        </details>
        {host.length > 0 && (
          // Only label the host bucket when there are also nested buckets to disambiguate.
          <GroupBlock label={hasNested ? "主机" : null} icon={Server} vulns={host} />
        )}
        {[...byParent.entries()].map(([parent, vs]) => (
          <GroupBlock key={parent} label={nestedLabel(parent)} icon={nestedIcon(parent)} vulns={vs} />
        ))}
        {hiddenFindingCount > 0 && (
          <div className="rounded-lg border border-dashed p-3 text-xs">
            <span className="text-muted-foreground">
              此卡仅预览严重度最高的 {vulns.length} / {allVulns.length} 项发现，另有{" "}
              {hiddenFindingCount} 项未在列表页渲染。
            </span>{" "}
            <Link
              href={`/reports/${encodeURIComponent(result.report_id)}`}
              className="font-medium text-primary hover:underline"
            >
              查看完整报告
            </Link>
          </div>
        )}
        {allVulns.length === 0 && (
          <p className="text-muted-foreground text-sm">
            {complete
              ? "这条派生记录的软件包漏洞检测已完成，当前记录未返回发现；列表不校验逻辑报告分片完整性。"
              : "当前记录未返回发现，且软件包漏洞检测覆盖不完整或未知。"}
          </p>
        )}
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
  const matches =
    source === "malware"
      ? (s: string) => MALWARE_SOURCES.has(s)
      : source === "defender"
        ? (s: string) => DEFENDER_SOURCES.has(s)
      : source === "mdvm"
        ? (s: string) => s === MDVM_SOURCE
      : source === "debian_tracker"
        ? (s: string) => s === "debian-security-tracker"
      : (s: string) => s === source;
  return results
    .map((r) => ({
      ...r,
      vulnerabilities: vulnsOf(r).filter((v) => matches(v.source)),
    }))
    .filter((r) => vulnsOf(r).length > 0);
}

export default async function VulnerabilitiesPage({
  searchParams,
}: {
  searchParams: Promise<{
    severity?: string | string[];
    source?: string | string[];
    page?: string | string[];
    cursor?: string | string[];
    trail?: string | string[];
  }>;
}) {
  const sp = await searchParams;
  const activeSeverity = parseMinSeverity(sp.severity);
  const activeSource = parseSource(sp.source);
  const page = parsePage(sp.page);
  const cursor = parseCursor(sp.cursor);
  const trail = parseCursorTrail(sp.trail);

  let results: DetectionResult[] = [];
  let nextCursor: string | null = null;
  let error: FormApiError | null = null;
  try {
    const result = await listVulnerabilitiesCursor(cursor, VULNERABILITY_RESULT_PAGE_SIZE);
    nextCursor = result.nextCursor;
    results = result.items;
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  const withFindings = results.filter((r) => vulnsOf(r).length > 0);
  const filtered = applySource(applyMinSeverity(results, activeSeverity), activeSource);
  const affectedHosts = new Set(withFindings.map((result) => result.host_id));
  const filteredHosts = new Set(
    filtered.filter((result) => vulnsOf(result).length > 0).map((result) => result.host_id),
  );
  // Record-scoped only: this list does not fetch lineage, so even a complete
  // record must not be promoted to a complete logical report.
  const recordCoverageIssues = results.filter(
    (result) => !detectionRecordComplete(result),
  ).length;
  const pageValues = {
    severity: activeSeverity,
    source: activeSource,
  };
  const { previousHref, nextHref } = cursorNavigation(
    "/vulnerabilities",
    page,
    cursor,
    nextCursor,
    trail,
    pageValues,
  );

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

  // 当前页已返回发现（不随筛选变化），不代表逻辑报告已完整汇总。
  const overall: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let overallTotal = 0;
  for (const r of withFindings) {
    for (const v of vulnsOf(r)) {
      overall[v.severity] += 1;
      overallTotal += 1;
    }
  }

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="漏洞发现"
        description="展示当前已返回的发现；实际范围取决于任务中启用的 OSV、Defender、MDVM、恶意文件、基线或密钥检测。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : results.length === 0 ? (
        <EmptyState
          icon={Bug}
          title="当前页暂无派生检测记录"
          description={
            page > 0
              ? "本页没有派生检测记录；可继续翻页或返回上一页，不能据此确认本次已启用检测无发现。"
              : "尚未收到 Analyzer 派生检测记录，不能据此确认本次已启用检测无发现。"
          }
        >
          {(page > 0 || nextCursor) && (
            <PageNav
              page={page}
              count={results.length}
              previousHref={previousHref}
              nextHref={nextHref}
            />
          )}
        </EmptyState>
      ) : (
        <div className="flex flex-col gap-6">
          {/* 当前页返回值概览，不推断完整逻辑报告。 */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <Stat
              icon={Bug}
              label="已返回发现"
              value={overallTotal}
              sublabel={`本页 ${affectedHosts.size} 台受影响主机`}
            />
            <Stat
              icon={ShieldAlert}
              label="严重"
              value={overall.critical}
              accent="text-red-600"
              sublabel="critical"
            />
            <Stat
              icon={TriangleAlert}
              label="高危"
              value={overall.high}
              accent="text-orange-500"
              sublabel="high"
            />
            <Stat
              icon={Server}
              label="受影响主机"
              value={affectedHosts.size}
              sublabel={`本页 ${withFindings.length} 份结果`}
            />
            <Stat
              icon={ShieldAlert}
              label="记录覆盖异常"
              value={recordCoverageIssues}
              accent={recordCoverageIssues > 0 ? "text-orange-500" : undefined}
              sublabel="OSV 未启用 / 部分 / 失败 / 截断"
            />
          </div>

          {/* 筛选工具栏 */}
          <div className="rounded-xl bg-card p-3 ring-1 ring-foreground/10 sm:p-4">
            <FilterBar severity={activeSeverity} source={activeSource} />
          </div>

          {filtered.length === 0 ? (
            <EmptyState
              icon={Bug}
              title="当前页没有符合条件的已返回发现"
              description="可调低最小严重度或切换来源；列表不校验逻辑报告分片完整性，因此不表示本次已启用检测无发现。"
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
                  {filteredHosts.size} 台主机
                </Badge>
                <Badge variant="outline">{filtered.length} 条派生记录</Badge>
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

          <PageNav
            page={page}
            count={results.length}
            previousHref={previousHref}
            nextHref={nextHref}
          />
        </div>
      )}
    </div>
  );
}
