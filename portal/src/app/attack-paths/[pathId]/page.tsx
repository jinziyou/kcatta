import Link from "next/link";
import { notFound } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FormApiError, getAttackPath } from "@/lib/api";
import type { AttackPath, AttackPathStep, Severity } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-black",
  low: "bg-slate-300 text-black",
  info: "bg-slate-200 text-black",
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge className={SEVERITY_CLASS[severity]}>{severity}</Badge>;
}

function FactChips({ facts, tone }: { facts: string[]; tone: "pre" | "post" }) {
  if (facts.length === 0) return null;
  const cls =
    tone === "post"
      ? "bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-100"
      : "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-200";
  return (
    <div className="flex flex-wrap gap-1">
      {facts.map((f) => (
        <Badge key={f} className={`${cls} font-mono text-[11px]`}>
          {f}
        </Badge>
      ))}
    </div>
  );
}

function StepCard({ step, index }: { step: AttackPathStep; index: number }) {
  const pre = step.preconditions_met ?? [];
  const post = step.postconditions_gained ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-base">
          <Badge variant="secondary">{index + 1}</Badge>
          {step.technique_id && <Badge variant="outline">{step.technique_id}</Badge>}
          {step.tactic && <span className="text-muted-foreground text-xs">{step.tactic}</span>}
          <span className="font-mono text-sm">{step.module_id}</span>
        </CardTitle>
        <CardDescription className="font-mono text-xs">
          on {step.host_label || step.host_id}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2 text-sm">
        {pre.length > 0 && (
          <div className="flex flex-col gap-1">
            <span className="text-muted-foreground text-xs">requires</span>
            <FactChips facts={pre} tone="pre" />
          </div>
        )}
        {post.length > 0 && (
          <div className="flex flex-col gap-1">
            <span className="text-muted-foreground text-xs">gains</span>
            <FactChips facts={post} tone="post" />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function IdList({ label, ids }: { label: string; ids: string[] }) {
  if (ids.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {label} ({ids.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col gap-1 font-mono text-xs">
          {ids.map((id) => (
            <li key={id}>{id}</li>
          ))}
        </ul>
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
    if (err instanceof FormApiError && err.status === 404) {
      notFound();
    }
    throw err;
  }

  const steps = path.steps ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <Link
        href="/attack-paths"
        className="text-muted-foreground hover:text-foreground mb-6 inline-block text-sm"
      >
        ← Attack paths
      </Link>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-base">
            <SeverityBadge severity={path.severity} />
            <Badge variant="secondary">score {path.score}</Badge>
            <Badge variant="outline">{steps.length} steps</Badge>
          </CardTitle>
          <CardDescription className="text-foreground/90 font-mono text-sm">
            {path.entry_host} → {path.goal_host}{" "}
            <span className="text-muted-foreground">(reaches {path.goal})</span>
          </CardDescription>
        </CardHeader>
        <CardContent className="text-muted-foreground/80 font-mono text-xs">
          {path.path_id}
        </CardContent>
      </Card>

      <h2 className="mb-3 text-sm font-semibold tracking-tight">Predicted kill chain</h2>
      <div className="mb-6 flex flex-col gap-0">
        {steps.map((step, i) => (
          <div key={`${step.module_id}-${step.host_id}-${i}`} className="flex flex-col">
            <StepCard step={step} index={i} />
            {i < steps.length - 1 && (
              <div className="text-muted-foreground self-center py-1 text-lg leading-none">↓</div>
            )}
          </div>
        ))}
      </div>

      <div className="grid gap-4">
        <IdList label="Hosts on path" ids={path.related_asset_ids ?? []} />
        <IdList label="Exploited vulnerabilities" ids={path.related_vuln_ids ?? []} />
      </div>
    </div>
  );
}
