import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { DetectionCoverage } from "@/lib/contracts";
import {
  COVERAGE_STATUS_LABEL,
  DETECTOR_LABEL,
  detectionReasonLabel,
} from "@/lib/detection";

function statusVariant(status: DetectionCoverage["status"]): "secondary" | "destructive" | "outline" {
  if (status === "complete") return "secondary";
  if (status === "failed") return "destructive";
  return "outline";
}

export function CoverageMatrix({ rows }: { rows: DetectionCoverage[] }) {
  if (rows.length === 0) {
    return (
      <p className="text-muted-foreground text-xs">
        该历史记录没有结构化覆盖信息，不能确认未返回发现的检测器是否实际运行。
      </p>
    );
  }
  return (
    <div className="overflow-hidden rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/40 hover:bg-muted/40">
            <TableHead>检测器</TableHead>
            <TableHead>生态 / 范围</TableHead>
            <TableHead>状态</TableHead>
            <TableHead className="text-right">已检测</TableHead>
            <TableHead className="text-right">跳过</TableHead>
            <TableHead className="text-right">发现</TableHead>
            <TableHead className="hidden lg:table-cell">说明</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row, index) => (
            <TableRow key={`${row.detector}:${row.ecosystem ?? "all"}:${index}`}>
              <TableCell className="font-medium">{DETECTOR_LABEL[row.detector]}</TableCell>
              <TableCell className="font-mono text-xs">{row.ecosystem ?? "本次任务"}</TableCell>
              <TableCell>
                <Badge variant={statusVariant(row.status)}>
                  {COVERAGE_STATUS_LABEL[row.status]}
                </Badge>
              </TableCell>
              <TableCell className="text-right tabular-nums">{row.scanned_count ?? 0}</TableCell>
              <TableCell className="text-right tabular-nums">{row.skipped_count ?? 0}</TableCell>
              <TableCell className="text-right tabular-nums">{row.finding_count ?? 0}</TableCell>
              <TableCell className="text-muted-foreground hidden text-xs lg:table-cell">
                {row.reason ? detectionReasonLabel(row.reason) : "—"}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
