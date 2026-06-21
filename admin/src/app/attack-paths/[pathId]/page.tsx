import { ArrowRight, Clock, GitBranch, Server, Target as TargetIcon } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { CopyableId } from "@/components/copy-button";
import { SeverityBadge } from "@/components/severity-badge";
import { Stat } from "@/components/stat";
import { Badge } from "@/components/ui/badge";
import { AttackGraph } from "@/components/attack-graph";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalyzerApiError, getAttackPath } from "@/lib/api";
import type { AttackPath, AttackPathStep } from "@/lib/contracts";
import { fmtTimestamp } from "@/lib/format";
import { SEVERITY_ACCENT } from "@/lib/meta";

export const dynamic = "force-dynamic";

function FactChips({
  label,
  facts,
  variant,
}: {
  label: string;
  facts: string[];
  variant: "outline" | "secondary";
}) {
  if (facts.length === 0) return null;
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-muted-foreground text-xs">{label}</span>
      <div className="flex flex-wrap gap-1">
        {facts.map((f) => (
          <Badge key={f} variant={variant} className="font-mono text-[11px]">
            {f}
          </Badge>
        ))}
      </div>
    </div>
  );
}

function StepCard({ step, index }: { step: AttackPathStep; index: number }) {
  const pre = step.preconditions_met ?? [];
  const post = step.postconditions_gained ?? [];
  return (
    <Card size="sm" className="gap-3">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          <span className="bg-muted text-muted-foreground inline-flex size-6 items-center justify-center rounded-full text-xs font-semibold tabular-nums">
            {index + 1}
          </span>
          <span className="font-mono">{step.host_label || step.host_id}</span>
          {step.tactic && (
            <Badge variant="secondary" className="font-normal">
              {step.tactic}
            </Badge>
          )}
          {step.technique_id && (
            <Badge variant="outline" className="font-mono">
              {step.technique_id}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        <div className="text-muted-foreground flex items-center gap-1.5 text-xs">
          <span>模块</span>
          <span className="text-foreground font-mono">{step.module_id}</span>
        </div>
        <FactChips label="前置条件" facts={pre} variant="outline" />
        <FactChips label="获得条件" facts={post} variant="secondary" />
      </CardContent>
    </Card>
  );
}

function IdSection({ label, ids }: { label: string; ids: string[] }) {
  if (ids.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {label}
          <span className="text-muted-foreground ml-1.5 text-sm font-normal tabular-nums">
            {ids.length}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-1.5">
          {ids.map((id) => (
            <Badge key={id} variant="outline" className="font-mono text-[11px]">
              {id}
            </Badge>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export default async function AttackPathPage({
  params,
}: {
  params: Promise<{ pathId: string }>;
}) {
  const { pathId } = await params;

  let path: AttackPath;
  try {
    path = await getAttackPath(pathId);
  } catch (err) {
    if (err instanceof AnalyzerApiError && err.status === 404) {
      notFound();
    }
    throw err;
  }

  const steps = path.steps ?? [];
  const assetIds = path.related_asset_ids ?? [];
  const vulnIds = path.related_vuln_ids ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-8">
      <nav className="lp-eyebrow mb-5 flex-wrap gap-x-2 gap-y-1" data-tick>
        <Link href="/attack-paths" className="hover:text-foreground transition-colors">
          攻击路径
        </Link>
        <span className="opacity-40" aria-hidden>
          /
        </span>
        <span className="text-foreground">路径详情</span>
      </nav>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-base">
            <SeverityBadge severity={path.severity} />
            <span className="inline-flex items-center gap-1.5 font-mono text-sm">
              <span>{path.entry_host}</span>
              <ArrowRight className="text-muted-foreground size-4 shrink-0" />
              <span>{path.goal_host}</span>
            </span>
          </CardTitle>
          <div className="text-muted-foreground flex items-center gap-1 text-xs">
            <span>路径</span>
            <CopyableId value={path.path_id} />
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="风险分" value={path.score} icon={TargetIcon} accent={SEVERITY_ACCENT[path.severity]} />
            <Stat label="步数" value={steps.length} icon={GitBranch} />
            <Stat
              label="目标事实"
              value={<span className="font-mono text-base">{path.goal}</span>}
              icon={Server}
            />
            <Stat
              label="生成时间"
              value={<span className="font-mono text-base">{fmtTimestamp(path.generated_at)}</span>}
              icon={Clock}
            />
          </div>
        </CardContent>
      </Card>

      <section className="mb-6 flex flex-col gap-3">
        <h2 className="font-heading text-lg leading-none font-medium tracking-tight">攻击图</h2>
        {steps.length > 0 ? (
          <AttackGraph steps={steps} severity={path.severity} />
        ) : (
          <p className="text-muted-foreground text-sm">该路径暂无可视化的步骤。</p>
        )}
      </section>

      {steps.length > 0 && (
        <section className="mb-6 flex flex-col gap-3">
          <h2 className="font-heading text-lg leading-none font-medium tracking-tight">逐跳步骤</h2>
          <ol className="flex flex-col gap-3">
            {steps.map((step, i) => (
              <li key={`${step.module_id}-${step.host_id}-${i}`}>
                <StepCard step={step} index={i} />
              </li>
            ))}
          </ol>
        </section>
      )}

      {(assetIds.length > 0 || vulnIds.length > 0) && (
        <div className="grid gap-4">
          <IdSection label="关联资产" ids={assetIds} />
          <IdSection label="利用的漏洞" ids={vulnIds} />
        </div>
      )}
    </div>
  );
}
