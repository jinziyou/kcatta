import { ArrowRight, ChevronRight, GitBranch } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState, ErrorState } from "@/components/states";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AnalyzerApiError, listAttackPaths } from "@/lib/api";
import type { AttackPath } from "@/lib/contracts";

export const dynamic = "force-dynamic";

export default async function AttackPathsPage() {
  let paths: AttackPath[] = [];
  let error: AnalyzerApiError | null = null;
  try {
    paths = await listAttackPaths(500);
  } catch (err) {
    error =
      err instanceof AnalyzerApiError
        ? err
        : new AnalyzerApiError(err instanceof Error ? err.message : String(err));
  }

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="攻击路径"
        description="基于已采集资产、漏洞与可达性，对照 ATT&CK 能力图谱推演出的、有据可循的攻击链路。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : paths.length === 0 ? (
        <EmptyState
          icon={GitBranch}
          title="尚未推演出攻击路径"
          description="攻击路径由已入库的资产报告与流量，结合红队能力图谱推演得到。先导入能力图谱，再回到此页查看。"
        />
      ) : (
        <section className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">攻击路径</h2>
            <span className="text-muted-foreground text-xs">{paths.length} 条路径</span>
          </div>
          <div className="overflow-hidden rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/40 hover:bg-muted/40">
                  <TableHead>严重度</TableHead>
                  <TableHead className="hidden sm:table-cell">风险分</TableHead>
                  <TableHead>入口 → 目标</TableHead>
                  <TableHead className="hidden md:table-cell">目标事实</TableHead>
                  <TableHead className="hidden sm:table-cell">步数</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {paths.map((path) => (
                  <TableRow key={path.path_id} className="group">
                    <TableCell>
                      <SeverityBadge severity={path.severity} />
                    </TableCell>
                    <TableCell className="hidden font-mono text-xs tabular-nums sm:table-cell">
                      {path.score}
                    </TableCell>
                    <TableCell>
                      <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                        <span>{path.entry_host}</span>
                        <ArrowRight className="text-muted-foreground size-3.5 shrink-0" />
                        <span>{path.goal_host}</span>
                      </span>
                    </TableCell>
                    <TableCell className="text-muted-foreground hidden font-mono text-xs md:table-cell">
                      {path.goal}
                    </TableCell>
                    <TableCell className="text-muted-foreground hidden font-mono text-xs tabular-nums sm:table-cell">
                      {path.steps?.length ?? 0}
                    </TableCell>
                    <TableCell>
                      <Link
                        href={`/attack-paths/${encodeURIComponent(path.path_id)}`}
                        aria-label="查看攻击路径详情"
                        className="text-muted-foreground hover:text-foreground inline-flex"
                      >
                        <ChevronRight className="size-4" />
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}
    </div>
  );
}
