"use client";

import { useActionState } from "react";

import { type ActionResult, registerTargetAction } from "@/app/targets/actions";
import { Button } from "@/components/ui/button";

const FIELD =
  "h-8 w-full rounded-lg border border-border bg-background px-2.5 text-sm outline-none transition-colors focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

function Labeled({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted-foreground">
      {label}
      {children}
    </label>
  );
}

export function RegisterTargetForm() {
  const [state, action, pending] = useActionState<ActionResult | null, FormData>(
    registerTargetAction,
    null,
  );

  return (
    <form action={action} className="flex flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Labeled label="Name">
          <input name="name" required placeholder="db-01" className={FIELD} />
        </Labeled>
        <Labeled label="Address (user@host)">
          <input name="address" required placeholder="root@10.0.0.9" className={FIELD} />
        </Labeled>
        <Labeled label="Port">
          <input name="port" type="number" defaultValue={22} min={1} className={FIELD} />
        </Labeled>
        <Labeled label="Transport">
          <select name="transport" defaultValue="ssh" className={FIELD}>
            <option value="ssh">ssh</option>
            <option value="winrm">winrm</option>
          </select>
        </Labeled>
        <Labeled label="Credential mode">
          <select name="credential_mode" defaultValue="managed_key" className={FIELD}>
            <option value="managed_key">managed_key (bootstrap via password)</option>
            <option value="identity">identity (server-side key path)</option>
          </select>
        </Labeled>
        <Labeled label="Identity path (identity mode)">
          <input name="identity_path" placeholder="/home/fusion/.ssh/id_ed25519" className={FIELD} />
        </Labeled>
        <div className="sm:col-span-2">
          <Labeled label="One-time password (managed_key bootstrap — never stored)">
            <input name="password" type="password" autoComplete="off" className={FIELD} />
          </Labeled>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <Button type="submit" disabled={pending}>
          {pending ? "Registering…" : "Register target"}
        </Button>
        {state?.ok && <span className="text-sm">Registered ✓</span>}
        {state?.error && <span className="text-destructive text-sm">{state.error}</span>}
      </div>
    </form>
  );
}
