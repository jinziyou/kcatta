import { Boxes, Bug, ChevronRight, FileText, Server } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/page-header";
import { Stat } from "@/components/stat";
import { RevealRows } from "@/components/reveal";
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
import { FormApiError, listAssetReports } from "@/lib/api";
import type { AssetReport } from "@/lib/contracts";
import { fmtTimestamp } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function ReportsPage() {
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

  const assetTotal = reports.reduce((n, r) => n + (r.assets?.length ?? 0), 0);
  const vulnTotal = reports.reduce((n, r) => n + (r.vulnerabilities?.length ?? 0), 0);
  const hostSet = new Set(reports.map((r) => r.host.hostname));

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="资产报告"
        description="主机扫描上报的资产快照，最新在前。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : reports.length === 0 ? (
        <EmptyState
          icon={Server}
          title="还没有资产报告"
          description="对主机运行资产采集类扫描后，最新的资产快照会出现在这里。"
        />
      ) : (
        <div className="flex flex-col gap-6">
          {/* KPI 概览条 */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat icon={FileText} label="资产报告" value={reports.length} sublabel="份快照" />
            <Stat icon={Boxes} label="资产总数" value={assetTotal} sublabel="累计资产项" />
            <Stat
              icon={Bug}
              label="漏洞发现"
              value={vulnTotal}
              accent={vulnTotal > 0 ? "text-red-600" : undefined}
              sublabel="累计漏洞"
            />
            <Stat icon={Server} label="覆盖主机" value={hostSet.size} sublabel="去重主机" />
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
              <RevealRows colSpan={6} initial={15} step={15}>
              {reports.map((report) => {
                const assetCount = report.assets?.length ?? 0;
                const vulnCount = report.vulnerabilities?.length ?? 0;
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
                        <Badge variant="destructive">{vulnCount}</Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
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
              </RevealRows>
            </TableBody>
          </Table>
          </div>
        </div>
      )}
    </div>
  );
}
