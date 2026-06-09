import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { RegisterTargetForm } from "@/components/register-target-form";
import { FusionApiError, listTargets } from "@/lib/api";
import type { ScanTarget } from "@/lib/contracts";

export const dynamic = "force-dynamic";

function fmt(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function TargetCard({ target }: { target: ScanTarget }) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3">
          <span className="truncate text-sm">{target.name}</span>
          <Badge variant="secondary">{target.transport}</Badge>
        </CardTitle>
        <CardDescription className="flex flex-col gap-1 font-mono text-xs">
          <span>{target.address}:{target.port}</span>
          <span className="text-muted-foreground/80">{target.target_id}</span>
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-2">
        <Badge variant="outline">{target.credential_mode}</Badge>
        <span className="text-muted-foreground text-xs">registered {fmt(target.created_at)}</span>
      </CardContent>
    </Card>
  );
}

export default async function TargetsPage() {
  let targets: ScanTarget[] = [];
  let error: FusionApiError | null = null;
  try {
    targets = await listTargets();
  } catch (err) {
    error =
      err instanceof FusionApiError
        ? err
        : new FusionApiError(err instanceof Error ? err.message : String(err));
  }

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <header className="mb-8 flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Targets</h1>
        <p className="text-muted-foreground text-sm">
          Hosts fusion can deploy the agent to. SSH/Linux; a one-time password bootstraps a managed
          key on the fusion host (never stored).
        </p>
      </header>

      {error ? (
        <Card className="border-destructive/40">
          <CardHeader>
            <CardTitle className="text-destructive">Cannot reach fusion API</CardTitle>
            <CardDescription>{error.message}</CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <div className="flex flex-col gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Register a target</CardTitle>
              <CardDescription>The credential stays on the fusion host.</CardDescription>
            </CardHeader>
            <CardContent>
              <RegisterTargetForm />
            </CardContent>
          </Card>

          {targets.length === 0 ? (
            <p className="text-muted-foreground text-sm">No targets registered yet.</p>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2">
              {targets.map((t) => (
                <TargetCard key={t.target_id} target={t} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
