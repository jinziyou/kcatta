import { KeyRound, Server, Target as TargetIcon, Terminal } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { RegisterTargetForm } from "@/components/register-target-form";
import { Stat } from "@/components/stat";
import { EmptyState, ErrorState } from "@/components/states";
import { TargetsTable } from "@/components/targets-table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FormApiError, listTargets } from "@/lib/api";
import type { ScanTarget } from "@/lib/contracts";

export const dynamic = "force-dynamic";

export default async function TargetsPage() {
  let targets: ScanTarget[] = [];
  let error: FormApiError | null = null;
  try {
    targets = await listTargets();
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  const sshCount = targets.filter((t) => t.transport === "ssh").length;
  const winrmCount = targets.filter((t) => t.transport === "winrm").length;
  const managedKeyCount = targets.filter((t) => t.credential_mode === "managed_key").length;

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="扫描目标"
        description="Form 可部署 agent 的主机清单（SSH / Linux）。托管密钥模式下，一次性密码仅用于在 Form 主机引导密钥，绝不落盘。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : (
        <div className="flex flex-col gap-8">
          {/* KPI 概览条 */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat icon={TargetIcon} label="注册目标" value={targets.length} sublabel="台主机" />
            <Stat icon={Terminal} label="SSH" value={sshCount} sublabel="ssh 传输" />
            <Stat icon={Server} label="WinRM" value={winrmCount} sublabel="winrm 传输" />
            <Stat icon={KeyRound} label="托管密钥" value={managedKeyCount} sublabel="managed_key" />
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">注册目标</CardTitle>
              <CardDescription>凭据始终保存在 Form 主机上。</CardDescription>
            </CardHeader>
            <CardContent>
              <RegisterTargetForm />
            </CardContent>
          </Card>

          <section className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">已注册目标</h2>
              <span className="text-muted-foreground text-xs">{targets.length} 台</span>
            </div>
            {targets.length === 0 ? (
              <EmptyState
                icon={TargetIcon}
                title="尚无注册目标"
                description="使用上方表单添加第一台主机后，即可下发扫描任务。"
              />
            ) : (
              <TargetsTable targets={targets} />
            )}
          </section>
        </div>
      )}
    </div>
  );
}
