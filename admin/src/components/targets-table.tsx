import { ScanLine } from "lucide-react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { ScanTarget } from "@/lib/contracts";
import { fmtTimestamp } from "@/lib/format";

/** Registry table of scan targets with a per-row shortcut into the scan form. */
export function TargetsTable({ targets }: { targets: ScanTarget[] }) {
  return (
    <div className="overflow-hidden rounded-xl border">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/40 hover:bg-muted/40">
            <TableHead>名称</TableHead>
            <TableHead>地址</TableHead>
            <TableHead className="hidden sm:table-cell">传输</TableHead>
            <TableHead className="hidden md:table-cell">凭据</TableHead>
            <TableHead className="hidden lg:table-cell">注册时间</TableHead>
            <TableHead className="w-20" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {targets.map((t) => (
            <TableRow key={t.target_id}>
              <TableCell className="font-medium">{t.name}</TableCell>
              <TableCell className="font-mono text-xs">
                {t.transport === "local" ? t.address : `${t.address}:${t.port}`}
              </TableCell>
              <TableCell className="hidden sm:table-cell">
                <Badge variant="secondary">{t.transport.toUpperCase()}</Badge>
              </TableCell>
              <TableCell className="hidden md:table-cell">
                <Badge variant="outline">
                  {t.transport === "local" ? "无需凭据" : t.credential_mode}
                </Badge>
              </TableCell>
              <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                {fmtTimestamp(t.created_at)}
              </TableCell>
              <TableCell>
                <Button size="xs" variant="ghost" render={<Link href="/scans" />}>
                  <ScanLine />
                  扫描
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
