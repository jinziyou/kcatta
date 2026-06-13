import { Target as TargetIcon } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { RegisterTargetForm } from "@/components/register-target-form";
import { EmptyState, ErrorState } from "@/components/states";
import { TargetsTable } from "@/components/targets-table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalyzerApiError, listTargets } from "@/lib/api";
import type { ScanTarget } from "@/lib/contracts";

export const dynamic = "force-dynamic";

export default async function TargetsPage() {
  let targets: ScanTarget[] = [];
  let error: AnalyzerApiError | null = null;
  try {
    targets = await listTargets();
  } catch (err) {
    error =
      err instanceof AnalyzerApiError
        ? err
        : new AnalyzerApiError(err instanceof Error ? err.message : String(err));
  }

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="扫描目标"
        description="analyzer 可部署 agent 的主机清单（SSH / Linux）。托管密钥模式下，一次性密码仅用于在 analyzer 主机引导密钥，绝不落盘。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : (
        <div className="flex flex-col gap-8">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">注册目标</CardTitle>
              <CardDescription>凭据始终保存在 analyzer 主机上。</CardDescription>
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
