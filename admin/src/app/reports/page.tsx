import { Boxes, Bug, ChevronRight, FileText, Server } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/page-header";
import { PageNav } from "@/components/page-nav";
import { Stat } from "@/components/stat";
import { EmptyState, ErrorState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FormApiError, getReportDetectionLineage, listAssetReportsCursor } from "@/lib/api";
import type { LineageResponse } from "@/lib/api";
import type { AssetReport, DetectionResult } from "@/lib/contracts";
import { detectionRecordComplete } from "@/lib/detection";
import { fmtTimestamp } from "@/lib/format";
import {
  cursorNavigation,
  parseCursor,
  parseCursorTrail,
  parsePage,
  REPORT_PAGE_SIZE,
} from "@/lib/pagination";
import { mergeVulnerabilities } from "@/lib/vulnerabilities";

export const dynamic = "force-dynamic";

type DetectionLookup =
  | { status: "found"; lineage: LineageResponse<DetectionResult> }
  | { status: "missing" }
  | { status: "error" };

async function lookupDetection(reportId: string): Promise<DetectionLookup> {
  try {
    return { status: "found", lineage: await getReportDetectionLineage(reportId) };
  } catch (error) {
    if (error instanceof FormApiError && error.status === 404) return { status: "missing" };
    return { status: "error" };
  }
}

function lookupComplete(lookup: DetectionLookup | undefined): boolean {
  return Boolean(
    lookup?.status === "found" &&
      lookup.lineage.complete === true &&
      lookup.lineage.records.length > 0 &&
      lookup.lineage.records.every(detectionRecordComplete),
  );
}

export default async function ReportsPage({
  searchParams,
}: {
  searchParams: Promise<{
    page?: string | string[];
    cursor?: string | string[];
    trail?: string | string[];
  }>;
}) {
  const params = await searchParams;
  const page = parsePage(params.page);
  const cursor = parseCursor(params.cursor);
  const trail = parseCursorTrail(params.trail);
  let reports: AssetReport[] = [];
  let nextCursor: string | null = null;
  let error: FormApiError | null = null;
  try {
    const result = await listAssetReportsCursor(cursor, REPORT_PAGE_SIZE);
    nextCursor = result.nextCursor;
    reports = result.items;
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  const detectionEntries = await Promise.all(
    reports.map(async (report) => [report.report_id, await lookupDetection(report.report_id)] as const),
  );
  const detections = new Map(detectionEntries);

  const assetTotal = reports.reduce((n, r) => n + (r.assets?.length ?? 0), 0);
  const vulnTotal = reports.reduce((n, report) => {
    const lookup = detections.get(report.report_id);
    const derived =
      lookup?.status === "found"
        ? lookup.lineage.records.flatMap((result) => result.vulnerabilities ?? [])
        : undefined;
    return n + mergeVulnerabilities(report.vulnerabilities, derived).length;
  }, 0);
  const hostSet = new Set(reports.map((r) => r.host.hostname));
  const unconfirmedReports = reports.filter(
    (report) => {
      const lookup = detections.get(report.report_id);
      return !lookupComplete(lookup);
    },
  ).length;
  const { previousHref, nextHref } = cursorNavigation(
    "/reports",
    page,
    cursor,
    nextCursor,
    trail,
    {},
  );

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="资产报告"
        description="主机扫描上报的资产快照，并按报告 ID 汇总 Analyzer 派生发现；支持翻阅完整历史。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : reports.length === 0 ? (
        <EmptyState
          icon={Server}
          title="还没有资产报告"
          description={
            page > 0
              ? "这一页没有资产报告，请返回上一页。"
              : "对主机运行资产采集类扫描后，最新的资产快照会出现在这里。"
          }
        >
          {page > 0 && <PageNav page={page} count={0} previousHref={previousHref} />}
        </EmptyState>
      ) : (
        <div className="flex flex-col gap-6">
          {/* KPI 概览条 */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat icon={FileText} label="资产报告" value={reports.length} sublabel="本页快照" />
            <Stat icon={Boxes} label="资产总数" value={assetTotal} sublabel="本页资产项" />
            <Stat
              icon={Bug}
              label="漏洞发现"
              value={vulnTotal}
              accent={vulnTotal > 0 ? "text-red-600" : undefined}
              sublabel={
                unconfirmedReports > 0
                  ? `已汇总；${unconfirmedReports} 份派生检测待确认`
                  : "本页已汇总发现"
              }
            />
            <Stat icon={Server} label="覆盖主机" value={hostSet.size} sublabel="本页去重主机" />
          </div>

          <div className="overflow-hidden rounded-xl border">
            <Table>
            <TableHeader>
              <TableRow className="bg-muted/40 hover:bg-muted/40">
                <TableHead>主机</TableHead>
                <TableHead className="hidden sm:table-cell">系统</TableHead>
                <TableHead className="text-right">资产数</TableHead>
                <TableHead className="text-right">漏洞</TableHead>
                <TableHead className="hidden md:table-cell">采集时间</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {reports.map((report) => {
                const assetCount = report.assets?.length ?? 0;
                const lookup = detections.get(report.report_id);
                const derived =
                  lookup?.status === "found"
                    ? lookup.lineage.records.flatMap((result) => result.vulnerabilities ?? [])
                    : undefined;
                const vulnCount = mergeVulnerabilities(report.vulnerabilities, derived).length;
                return (
                  <TableRow key={report.report_id} className="group">
                    <TableCell className="font-mono text-xs font-medium">
                      {report.host.hostname}
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <Badge variant="secondary">{report.host.os}</Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{assetCount}</TableCell>
                    <TableCell className="text-right">
                      {vulnCount > 0 ? (
                        <span className="inline-flex flex-wrap justify-end gap-1">
                          <Badge variant="destructive">{vulnCount}</Badge>
                          {lookup?.status === "found" ? (
                            !lookupComplete(lookup) && (
                              <Badge variant="outline">完整性未确认</Badge>
                            )
                          ) : (
                            <Badge variant="outline">派生检测待确认</Badge>
                          )}
                        </span>
                      ) : lookupComplete(lookup) ? (
                        <Badge variant="secondary">0</Badge>
                      ) : lookup?.status === "found" ? (
                        <Badge variant="outline">0 · 完整性未确认</Badge>
                      ) : lookup?.status === "error" ? (
                        <Badge variant="outline">检测不可用</Badge>
                      ) : (
                        <Badge variant="outline">未生成检测记录</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground hidden font-mono text-xs md:table-cell">
                      {fmtTimestamp(report.collected_at)}
                    </TableCell>
                    <TableCell>
                      <Link
                        href={`/reports/${encodeURIComponent(report.report_id)}`}
                        aria-label="查看资产报告详情"
                        className="text-muted-foreground hover:text-foreground inline-flex"
                      >
                        <ChevronRight className="size-4" />
                      </Link>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
          </div>

          <PageNav
            page={page}
            count={reports.length}
            previousHref={previousHref}
            nextHref={nextHref}
          />
        </div>
      )}
    </div>
  );
}
