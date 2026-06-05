import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FormApiError, listAttackPaths } from "@/lib/api";
import type { AttackPath, Severity } from "@/lib/contracts";

export const dynamic = "force-dynamic";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

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

function Summary({ paths }: { paths: AttackPath[] }) {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const path of paths) counts[path.severity] += 1;
  return (
    <div className="mb-6 flex flex-wrap items-center gap-2">
      <Badge variant="outline">{paths.length} paths</Badge>
      {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
        <Badge key={s} className={SEVERITY_CLASS[s]}>
          {s}: {counts[s]}
        </Badge>
      ))}
    </div>
  );
}

function PathCard({ path }: { path: AttackPath }) {
  const steps = path.steps ?? [];
  const vulnIds = path.related_vuln_ids ?? [];
  const chain = steps.map((s) => s.technique_id || s.module_id).join(" → ");

  return (
    <Link href={`/attack-paths/${encodeURIComponent(path.path_id)}`}>
      <Card className="transition-colors hover:bg-muted/30">
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-base leading-snug">
            <SeverityBadge severity={path.severity} />
            <Badge variant="secondary">score {path.score}</Badge>
            <Badge variant="outline">{steps.length} steps</Badge>
          </CardTitle>
          <CardDescription className="text-foreground/90 font-mono text-sm">
            {path.entry_host} → {path.goal_host}{" "}
            <span className="text-muted-foreground">({path.goal})</span>
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 text-sm">
          {chain && <p className="text-muted-foreground font-mono text-xs">{chain}</p>}
          <div className="flex flex-wrap gap-2">
            {vulnIds.length > 0 && <Badge variant="outline">{vulnIds.length} vuln(s)</Badge>}
            <Badge variant="outline">{(path.related_asset_ids ?? []).length} host(s)</Badge>
          </div>
          <div className="text-muted-foreground/80 font-mono text-xs">{path.path_id}</div>
        </CardContent>
      </Card>
    </Link>
  );
}

function EmptyState() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>No attack paths predicted</CardTitle>
        <CardDescription>
          Attack paths are derived from ingested posture (asset reports + flows) and a red-team
          capability graph. Ingest a capability graph, then revisit this page.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="bg-muted overflow-x-auto rounded-md p-3 font-mono text-xs">
          att7ck export-capability-graph -o cg.json{"\n"}
          curl -XPOST http://127.0.0.1:8000/ingest/capability-graph -d @cg.json
        </pre>
      </CardContent>
    </Card>
  );
}

function ErrorState({ error }: { error: FormApiError }) {
  return (
    <Card className="border-destructive/40">
      <CardHeader>
        <CardTitle className="text-destructive">Cannot reach form API</CardTitle>
        <CardDescription>{error.message}</CardDescription>
      </CardHeader>
      <CardContent className="text-muted-foreground text-sm">
        Make sure <span className="font-mono">form-api</span> is running and that
        <span className="font-mono"> NEXT_PUBLIC_FORM_BASE_URL</span> points at it.
      </CardContent>
    </Card>
  );
}

export default async function AttackPathsPage() {
  let paths: AttackPath[] = [];
  let error: FormApiError | null = null;
  try {
    paths = await listAttackPaths(200);
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <header className="mb-8 flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Attack paths</h1>
        <p className="text-muted-foreground text-sm">
          Posture-grounded attack paths predicted from observed assets, vulnerabilities, and
          reachability against the ingested ATT&amp;CK capability graph.
        </p>
      </header>

      {error ? (
        <ErrorState error={error} />
      ) : paths.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <Summary paths={paths} />
          <div className="grid gap-4">
            {paths.map((path) => (
              <PathCard key={path.path_id} path={path} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
