"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { toast } from "sonner";

import { triageAlertAction } from "@/app/alerts/actions";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { AlertStatus } from "@/lib/contracts";
import { ALERT_STATUS_META } from "@/lib/meta";

const STATUS_OPTIONS: AlertStatus[] = ["open", "acknowledged", "closed"];

/** Triage controls for one alert: status / assignee / note / suppress. */
export function AlertTriageForm({
  alertKey,
  initialStatus,
  initialAssignee,
  initialNote,
  initialSuppressed,
}: {
  alertKey: string;
  initialStatus: AlertStatus;
  initialAssignee: string;
  initialNote: string;
  initialSuppressed: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [status, setStatus] = useState<AlertStatus>(initialStatus);
  const [assignee, setAssignee] = useState(initialAssignee);
  const [note, setNote] = useState(initialNote);
  const [suppressed, setSuppressed] = useState(initialSuppressed);

  function submit() {
    startTransition(async () => {
      const result = await triageAlertAction(alertKey, {
        status,
        assignee: assignee.trim() || null,
        note: note.trim() || null,
        suppressed,
      });
      if (result.ok) {
        toast.success("已更新处置状态");
        router.refresh();
      } else {
        toast.error("更新失败", { description: result.error });
      }
    });
  }

  return (
    <FieldGroup>
      <div className="grid gap-5 sm:grid-cols-2">
        <Field>
          <FieldLabel htmlFor="a-status">状态</FieldLabel>
          <Select value={status} onValueChange={(v) => setStatus(v as AlertStatus)}>
            <SelectTrigger id="a-status" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map((s) => (
                <SelectItem key={s} value={s}>
                  {ALERT_STATUS_META[s].label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field>
          <FieldLabel htmlFor="a-assignee">处置人</FieldLabel>
          <Input
            id="a-assignee"
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            placeholder="未指派"
          />
        </Field>
        <Field className="sm:col-span-2">
          <FieldLabel htmlFor="a-note">处置备注</FieldLabel>
          <Input
            id="a-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="研判结论 / 处置说明"
          />
        </Field>
        <Field orientation="horizontal" className="sm:col-span-2">
          <Switch checked={suppressed} onCheckedChange={(v) => setSuppressed(v)} />
          <div>
            <FieldLabel>抑制此告警</FieldLabel>
            <FieldDescription>抑制后默认从列表隐藏（可在列表「显示已抑制」中查看）。</FieldDescription>
          </div>
        </Field>
      </div>

      <div className="flex items-center gap-3 border-t pt-4">
        <Button onClick={submit} disabled={pending}>
          {pending ? "保存中…" : "保存处置"}
        </Button>
      </div>
    </FieldGroup>
  );
}
