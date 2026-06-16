"use client";

import { RefreshCw, ShieldAlert, ShieldOff } from "lucide-react";
import { useState, useTransition } from "react";
import { toast } from "sonner";

import { guardStatusAction, stopGuardAction } from "@/app/targets/guard-actions";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import type { GuardLifecycleStatus } from "@/lib/contracts";

/**
 * Resident guard daemon lifecycle for one SSH target: open the panel to probe
 * status (on first open), refresh, and stop+uninstall. Start lives in the scan
 * form (执行模式=常驻); this is the 状态 + 停止-卸载 half of the lifecycle.
 */
export function GuardControl({ targetId, address }: { targetId: string; address: string }) {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<GuardLifecycleStatus | null>(null);
  const [pending, startTransition] = useTransition();

  function refresh() {
    startTransition(async () => {
      const r = await guardStatusAction(targetId);
      if (r.ok) setStatus(r.status);
      else toast.error("状态获取失败", { description: r.error });
    });
  }

  function stop() {
    startTransition(async () => {
      const r = await stopGuardAction(targetId);
      if (r.ok) {
        setStatus(r.status);
        toast.success("已停止常驻守护进程", { description: r.status.detail });
      } else {
        toast.error("停止失败", { description: r.error });
      }
    });
  }

  function onOpenChange(next: boolean) {
    setOpen(next);
    // Re-probe on every open (the daemon is a live remote process — a cached
    // status from a previous open can lie); drop stale status on close.
    if (next) refresh();
    else setStatus(null);
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetTrigger render={<Button size="xs" variant="ghost" />}>
        <ShieldAlert />
        常驻
      </SheetTrigger>
      <SheetContent>
        <SheetHeader>
          <SheetTitle>常驻守护进程</SheetTitle>
          <SheetDescription className="font-mono">{address}</SheetDescription>
        </SheetHeader>
        <div className="flex flex-col gap-3 px-4 text-sm">
          {status ? (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2">
                <Badge variant={status.alive ? "default" : "outline"}>
                  {status.alive ? "运行中" : "未运行"}
                </Badge>
                <span className="text-muted-foreground text-xs">
                  {status.supervisor}
                  {status.pid ? ` · pid ${status.pid}` : ""}
                </span>
              </div>
              {status.detail && (
                <p className="text-muted-foreground text-xs break-words">{status.detail}</p>
              )}
            </div>
          ) : (
            <p className="text-muted-foreground text-xs">{pending ? "查询中…" : "尚无状态"}</p>
          )}

          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={refresh} disabled={pending}>
              <RefreshCw />
              刷新状态
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={stop}
              // Only enabled once a status is loaded AND the daemon is positively
              // alive — never destructive against an unconfirmed/unreachable host.
              disabled={pending || !status || !status.alive}
            >
              <ShieldOff />
              停止并卸载
            </Button>
          </div>

          <p className="text-muted-foreground text-xs">
            「停止并卸载」会停止 systemd 单元 / 守护进程并删除目标上的安装目录。需要重新启用时，在「任务配置与下发」中选择执行模式=常驻即可。
          </p>
        </div>
      </SheetContent>
    </Sheet>
  );
}
