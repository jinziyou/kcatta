import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FusionApiError, listGuardEvents } from "@/lib/api";
import type { GuardEventBatch } from "@/lib/contracts";

export const dynamic = "force-dynamic";

type GuardEvent = NonNullable<GuardEventBatch["events"]>[number];

function fmt(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function sevVariant(sev: string): "destructive" | "secondary" | "outline" {
  if (sev === "critical" || sev === "high") return "destructive";
  if (sev === "medium") return "secondary";
  return "outline";
}

function EventRow({ event }: { event: GuardEvent }) {
  return (
    <li className="flex flex-wrap items-center gap-2 font-mono text-xs">
      <Badge variant="secondary">{event.kind}</Badge>
      <Badge variant={sevVariant(event.severity)}>{event.severity}</Badge>
      <span className="text-muted-foreground">{fmt(event.timestamp)}</span>
      <span>action={event.action_taken}</span>
      <span className="text-muted-foreground">outcome={event.outcome}</span>
    </li>
  );
}

function BatchCard({ batch }: { batch: GuardEventBatch }) {
  const events = batch.events ?? [];
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3 text-sm">
          <span className="font-mono">{batch.host_id}</span>
          <Badge variant="outline">{events.length} events</Badge>
        </CardTitle>
        <CardDescription className="flex flex-col gap-0.5 font-mono text-xs">
          <span>batch {batch.batch_id}</span>
          <span>collected {fmt(batch.collected_at)} · agent v{batch.agent_version}</span>
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col gap-1.5">
          {events.map((event) => (
            <EventRow key={event.event_id} event={event} />
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

export default async function GuardPage({
  searchParams,
}: {
  searchParams: Promise<{ host?: string }>;
}) {
  const { host } = await searchParams;

  let batches: GuardEventBatch[] = [];
  let error: FusionApiError | null = null;
  try {
    batches = await listGuardEvents(host);
  } catch (err) {
    error =
      err instanceof FusionApiError
        ? err
        : new FusionApiError(err instanceof Error ? err.message : String(err));
  }

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-10">
      <header className="mb-8 flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Guard events</h1>
        <p className="text-muted-foreground text-sm">
          Real-time protection events streamed by <span className="font-mono">posture-guard</span>
          {host ? (
            <>
              {" "}
              for <span className="font-mono">{host}</span>
            </>
          ) : null}
          , newest first.
        </p>
      </header>

      {error ? (
        <Card className="border-destructive/40">
          <CardHeader>
            <CardTitle className="text-destructive">Cannot reach fusion API</CardTitle>
            <CardDescription>{error.message}</CardDescription>
          </CardHeader>
        </Card>
      ) : batches.length === 0 ? (
        <p className="text-muted-foreground text-sm">
          No guard events yet. Trigger a guard scan from the Scans page to start a daemon.
        </p>
      ) : (
        <div className="grid gap-3">
          {batches.map((batch) => (
            <BatchCard key={batch.batch_id} batch={batch} />
          ))}
        </div>
      )}
    </div>
  );
}
