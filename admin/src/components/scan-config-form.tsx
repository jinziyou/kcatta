"use client";

import { Cpu, Network, Play, Repeat, ShieldAlert, Target as TargetIcon, Zap } from "lucide-react";
import { useRouter } from "next/navigation";
import { useMemo, useState, useTransition } from "react";
import { toast } from "sonner";

import { triggerScanAction } from "@/app/scans/actions";
import { Button } from "@/components/ui/button";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { ScanCapability, ScanJobOptions, ScanMode, ScanTarget } from "@/lib/contracts";
import { CAPABILITY_META, MODE_CAPABILITIES, MODE_META, MODE_ORDER } from "@/lib/meta";
import { cn } from "@/lib/utils";

const MODE_ICON: Record<ScanMode, typeof Zap> = {
  oneshot: Zap,
  resident: Repeat,
};

const CAP_ICON: Record<ScanCapability, typeof Cpu> = {
  host: Cpu,
  trace: Network,
  guard: ShieldAlert,
};

const DEFAULTS: ScanJobOptions = {
  scan_target: "all",
  malware: true,
  pcap: false,
  iface: "any",
  duration: 5,
  bpf: "tcp or udp or icmp",
};

export function ScanConfigForm({ targets }: { targets: ScanTarget[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  const [targetId, setTargetId] = useState<string>(targets[0]?.target_id ?? "");
  const [mode, setMode] = useState<ScanMode>("oneshot");
  const [capability, setCapability] = useState<ScanCapability>("host");
  const [opts, setOpts] = useState<ScanJobOptions>(DEFAULTS);

  const selectedTarget = useMemo(
    () => targets.find((t) => t.target_id === targetId),
    [targets, targetId],
  );
  // local 与 winrm 都只支持单次 host：常驻/trace 需在目标侧部署常驻 agent（仅 SSH）。
  const isLocalTarget = selectedTarget?.transport === "local";
  const isHostOnlyTarget = isLocalTarget || selectedTarget?.transport === "winrm";
  const modeCapabilities = MODE_CAPABILITIES[mode];

  function selectTarget(id: string) {
    setTargetId(id);
    const next = targets.find((t) => t.target_id === id);
    if (next && (next.transport === "local" || next.transport === "winrm")) {
      // local/winrm 只支持单次 host；常驻/trace 仅适用于 SSH 目标。
      setMode("oneshot");
      setCapability("host");
    }
  }

  function changeMode(next: ScanMode) {
    setMode(next);
    const allowed = MODE_CAPABILITIES[next];
    if (!allowed.includes(capability)) setCapability(allowed[0]);
  }

  function set<K extends keyof ScanJobOptions>(key: K, value: ScanJobOptions[K]) {
    setOpts((prev) => ({ ...prev, [key]: value }));
  }

  function dispatch() {
    if (!targetId) {
      toast.error("请先选择扫描目标");
      return;
    }
    const options: Partial<ScanJobOptions> =
      capability === "host"
        ? { scan_target: opts.scan_target, malware: opts.malware }
        : capability === "trace"
          ? { pcap: opts.pcap, iface: opts.iface, duration: opts.duration, bpf: opts.bpf }
          : {};

    startTransition(async () => {
      const result = await triggerScanAction({ target_id: targetId, capability, options });
      if (result.ok) {
        toast.success("任务已下发", {
          description: `${CAPABILITY_META[capability].label} → ${selectedTarget?.name ?? targetId}`,
        });
        router.push(`/scans/${encodeURIComponent(result.jobId)}`);
      } else {
        toast.error("下发失败", { description: result.error });
      }
    });
  }

  return (
    <FieldGroup>
      {/* ---- target ---- */}
      <Field>
        <FieldLabel htmlFor="scan-target">扫描目标</FieldLabel>
        <Select value={targetId} onValueChange={(v) => selectTarget(v as string)}>
          <SelectTrigger id="scan-target" className="w-full">
            <SelectValue placeholder="选择已注册的目标" />
          </SelectTrigger>
          <SelectContent>
            {targets.map((t) => (
              <SelectItem key={t.target_id} value={t.target_id}>
                <TargetIcon className="text-muted-foreground" />
                <span className="font-medium">{t.name}</span>
                <span className="text-muted-foreground font-mono text-xs">{t.address}</span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {selectedTarget && (
          <FieldDescription>
            {isLocalTarget ? (
              <>LOCAL · {selectedTarget.address} · 本机就地扫描，无需凭据</>
            ) : (
              <>
                {selectedTarget.transport.toUpperCase()} · {selectedTarget.address}:
                {selectedTarget.port} · 凭据 {selectedTarget.credential_mode}
              </>
            )}
          </FieldDescription>
        )}
      </Field>

      {/* ---- execution mode (单次 / 常驻) ---- */}
      <FieldSet>
        <FieldLegend variant="label">执行模式</FieldLegend>
        <div role="radiogroup" aria-label="执行模式" className="grid gap-2 sm:grid-cols-2">
          {MODE_ORDER.map((m) => {
            const meta = MODE_META[m];
            const Icon = MODE_ICON[m];
            const active = mode === m;
            // 常驻代理需在目标侧部署 daemon over SSH：local/winrm 不支持。
            const disabled = isHostOnlyTarget && m === "resident";
            return (
              <button
                key={m}
                type="button"
                role="radio"
                aria-checked={active}
                disabled={disabled}
                title={disabled ? "常驻代理仅支持 SSH 目标" : undefined}
                onClick={() => changeMode(m)}
                className={cn(
                  "flex flex-col gap-1.5 rounded-lg border p-3 text-left transition-colors outline-none",
                  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
                  "disabled:cursor-not-allowed disabled:opacity-50",
                  active
                    ? "border-primary/40 bg-primary/5 dark:bg-primary/10"
                    : "hover:bg-muted/50 border-border",
                )}
              >
                <div className="flex items-center gap-2">
                  <Icon
                    className={cn("size-4", active ? "text-primary" : "text-muted-foreground")}
                  />
                  <span className="text-sm font-medium">{meta.label}</span>
                </div>
                <span className="text-muted-foreground text-xs leading-snug">
                  {meta.description}
                </span>
              </button>
            );
          })}
        </div>
      </FieldSet>

      {/* ---- capability (filtered by mode) ---- */}
      <FieldSet>
        <FieldLegend variant="label">检测能力</FieldLegend>
        <div role="radiogroup" aria-label="检测能力" className="grid gap-2 sm:grid-cols-2">
          {modeCapabilities.map((cap) => {
            const meta = CAPABILITY_META[cap];
            const Icon = CAP_ICON[cap];
            const active = capability === cap;
            // local/winrm 仅支持 host；trace 需在目标侧采集（SSH）。
            const disabled = isHostOnlyTarget && cap !== "host";
            return (
              <button
                key={cap}
                type="button"
                role="radio"
                aria-checked={active}
                disabled={disabled}
                title={disabled ? "该目标仅支持主机能力" : undefined}
                onClick={() => setCapability(cap)}
                className={cn(
                  "flex flex-col gap-1.5 rounded-lg border p-3 text-left transition-colors outline-none",
                  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
                  "disabled:cursor-not-allowed disabled:opacity-50",
                  active
                    ? "border-primary/40 bg-primary/5 dark:bg-primary/10"
                    : "hover:bg-muted/50 border-border",
                )}
              >
                <div className="flex items-center gap-2">
                  <Icon className={cn("size-4", active ? "text-primary" : "text-muted-foreground")} />
                  <span className="text-sm font-medium">{meta.label}</span>
                </div>
                <span className="text-muted-foreground text-xs leading-snug">{meta.description}</span>
              </button>
            );
          })}
        </div>
      </FieldSet>

      {/* ---- capability options ---- */}
      <CapabilityOptions capability={capability} opts={opts} set={set} />

      {/* ---- dispatch ---- */}
      <div className="flex flex-wrap items-center gap-3 border-t pt-4">
        <Button onClick={dispatch} disabled={pending || !targetId}>
          <Play />
          {pending ? "下发中…" : "下发任务"}
        </Button>
        <span className="text-muted-foreground text-xs">
          {isLocalTarget
            ? `下发后 analyzer 将在本机就地运行 agent 并采集 ${CAPABILITY_META[capability].produces}。`
            : `下发后 analyzer 将远程部署 agent 并采集 ${CAPABILITY_META[capability].produces}。`}
        </span>
      </div>
    </FieldGroup>
  );
}

function CapabilityOptions({
  capability,
  opts,
  set,
}: {
  capability: ScanCapability;
  opts: ScanJobOptions;
  set: <K extends keyof ScanJobOptions>(key: K, value: ScanJobOptions[K]) => void;
}) {
  if (capability === "host") {
    return (
      <FieldSet className="rounded-lg border bg-muted/30 p-4">
        <FieldLegend variant="label">主机扫描选项</FieldLegend>
        <Field orientation="vertical">
          <FieldLabel htmlFor="scan-object">扫描对象</FieldLabel>
          <Input
            id="scan-object"
            value={opts.scan_target}
            onChange={(e) => set("scan_target", e.target.value)}
            placeholder="all"
            className="font-mono"
          />
          <FieldDescription>
            agent <span className="font-mono">-t</span> 参数：<span className="font-mono">all</span>{" "}
            采集全部资产，或指定路径/对象。
          </FieldDescription>
        </Field>
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="malware">恶意文件检测</FieldLabel>
            <FieldDescription>对采集到的文件执行内置签名扫描（含 EICAR）。</FieldDescription>
          </FieldContent>
          <Switch
            id="malware"
            checked={opts.malware}
            onCheckedChange={(v) => set("malware", v)}
          />
        </Field>
      </FieldSet>
    );
  }

  if (capability === "trace") {
    return (
      <FieldSet className="rounded-lg border bg-muted/30 p-4">
        <FieldLegend variant="label">流量采集选项</FieldLegend>
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="pcap">实时抓包</FieldLabel>
            <FieldDescription>关闭时使用内置的模拟流量样本，便于联调演示。</FieldDescription>
          </FieldContent>
          <Switch id="pcap" checked={opts.pcap} onCheckedChange={(v) => set("pcap", v)} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field>
            <FieldLabel htmlFor="iface">监听网卡</FieldLabel>
            <Input
              id="iface"
              value={opts.iface}
              onChange={(e) => set("iface", e.target.value)}
              placeholder="any"
              className="font-mono"
              disabled={!opts.pcap}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="duration">抓包时长（秒）</FieldLabel>
            <Input
              id="duration"
              type="number"
              min={1}
              value={opts.duration}
              onChange={(e) => set("duration", Number(e.target.value) || DEFAULTS.duration)}
              className="font-mono"
              disabled={!opts.pcap}
            />
          </Field>
        </div>
        <Field>
          <FieldLabel htmlFor="bpf">BPF 过滤表达式</FieldLabel>
          <Input
            id="bpf"
            value={opts.bpf}
            onChange={(e) => set("bpf", e.target.value)}
            placeholder="tcp or udp or icmp"
            className="font-mono"
            disabled={!opts.pcap}
          />
          <FieldDescription>仅在实时抓包模式下生效。</FieldDescription>
        </Field>
      </FieldSet>
    );
  }

  return (
    <div className="bg-muted/30 text-muted-foreground flex items-start gap-2 rounded-lg border p-4 text-sm">
      <ShieldAlert className="text-foreground mt-0.5 size-4 shrink-0" />
      <p>
        实时防护将在目标上启动 <span className="font-mono">agent-guard</span>{" "}
        常驻守护进程，持续监控并把事件推送回 analyzer。任务下发后即视为成功，事件流可在「防护事件」页查看。
      </p>
    </div>
  );
}
