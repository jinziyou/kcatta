"use client";

import { useActionState, useState } from "react";

import { type TriggerResult, triggerScanAction } from "@/app/scans/actions";
import { Button } from "@/components/ui/button";
import type { ScanCapability, ScanTarget } from "@/lib/contracts";

const FIELD =
  "h-8 w-full rounded-lg border border-border bg-background px-2.5 text-sm outline-none transition-colors focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

export function TriggerScanForm({ targets }: { targets: ScanTarget[] }) {
  const [state, action, pending] = useActionState<TriggerResult | null, FormData>(
    triggerScanAction,
    null,
  );
  const [capability, setCapability] = useState<ScanCapability>("host");

  if (targets.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">
        No targets registered yet —{" "}
        <a href="/targets" className="text-primary underline">
          register one
        </a>{" "}
        first.
      </p>
    );
  }

  return (
    <form action={action} className="flex flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          Target
          <select name="target_id" required className={FIELD} defaultValue={targets[0].target_id}>
            {targets.map((t) => (
              <option key={t.target_id} value={t.target_id}>
                {t.name} ({t.address})
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          Capability
          <select
            name="capability"
            value={capability}
            onChange={(e) => setCapability(e.target.value as ScanCapability)}
            className={FIELD}
          >
            <option value="host">host — static file detection</option>
            <option value="flow">flow — traffic capture</option>
            <option value="guard">guard — real-time protection daemon</option>
          </select>
        </label>
        {capability === "host" && (
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            Scan object
            <input name="scan_target" defaultValue="all" className={FIELD} />
          </label>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-4 text-sm">
        {capability === "host" && (
          <label className="flex items-center gap-2">
            <input type="checkbox" name="malware" defaultChecked /> malware scan
          </label>
        )}
        {capability === "flow" && (
          <label className="flex items-center gap-2">
            <input type="checkbox" name="pcap" /> live pcap (else mock)
          </label>
        )}
        {capability === "guard" && (
          <span className="text-muted-foreground">
            starts a persistent daemon that pushes events to fusion
          </span>
        )}
      </div>
      <div className="flex items-center gap-3">
        <Button type="submit" disabled={pending}>
          {pending ? "Triggering…" : "Trigger scan"}
        </Button>
        {state?.error && <span className="text-destructive text-sm">{state.error}</span>}
      </div>
    </form>
  );
}
