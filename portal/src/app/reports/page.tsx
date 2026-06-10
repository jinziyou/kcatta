import { ChevronRight, Server } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/page-header";
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
import { FusionApiError, listAssetReports } from "@/lib/api";
import type { AssetReport } from "@/lib/contracts";
import { fmtTimestamp } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function ReportsPage() {
  let reports: AssetReport[] = [];
  let error: FusionApiError | null = null;
  try {
    reports = await listAssetReports(50);
  } catch (err) {
    error =
      err instanceof FusionApiError
        ? err
        : new FusionApiError(err instanceof Error ? err.message : String(err));
  }

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
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
