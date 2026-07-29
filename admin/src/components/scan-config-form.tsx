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
import type {
  ScanCapability,
  ScanJobOptions,
  ScanMode,
  ScanTarget,
  WindowsDefenderScan,
} from "@/lib/contracts";
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

type AdminScanOptions = ScanJobOptions & {
  /** Host posture checks are enabled by default by the Form contract. */
  posture: boolean;
  /** Secret scanning is explicit opt-in and only uploads fingerprints/evidence. */
  secrets: boolean;
  /** Enrich trace events with Form's managed IOC feed. */
  intel: boolean;
  /** Collect file/process trace streams; requires a capable Linux build/privileges. */
  ebpf: boolean;
  /** Enable Guard network IOC and IDS monitors. */
  guard_network: boolean;
  /** Enable Guard on-access malware scanning when the deployed build supports it. */
  guard_onaccess: boolean;
};

const DEFAULTS: AdminScanOptions = {
  scan_target: "all",
  malware: true,
  windows_defender_scan: "quick",
  posture: true,
  secrets: false,
  pcap: false,
  iface: "any",
  duration: 5,
  bpf: "tcp or udp or icmp",
  intel: true,
  ebpf: false,
  guard_network: true,
  guard_onaccess: false,
};

export function ScanConfigForm({ targets }: { targets: ScanTarget[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  const [targetId, setTargetId] = useState<string>(targets[0]?.target_id ?? "");
  const [mode, setMode] = useState<ScanMode>("oneshot");
  const [capability, setCapability] = useState<ScanCapability>("host");
  const [opts, setOpts] = useState<AdminScanOptions>(DEFAULTS);

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

  function set<K extends keyof AdminScanOptions>(key: K, value: AdminScanOptions[K]) {
    setOpts((prev) => ({ ...prev, [key]: value }));
  }

  function dispatch() {
    if (!targetId) {
      toast.error("请先选择扫描目标");
      return;
    }
    const options: Partial<AdminScanOptions> =
      capability === "host"
        ? {
            scan_target: opts.scan_target,
            malware: opts.malware,
            ...(selectedTarget?.transport === "winrm"
              ? { windows_defender_scan: opts.windows_defender_scan }
              : {}),
            posture: opts.posture,
            secrets: opts.secrets,
          }
        : capability === "trace"
          ? {
              pcap: opts.pcap,
              iface: opts.iface,
              duration: opts.duration,
              bpf: opts.bpf,
              intel: opts.intel,
              ebpf: opts.ebpf,
            }
          : {
              guard_network: opts.guard_network,
              guard_onaccess: opts.guard_onaccess,
            };

    startTransition(async () => {
      const result = await triggerScanAction({
        target_id: targetId,
        capability,
        options,
        request_id: crypto.randomUUID(),
      });
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
      <CapabilityOptions
        capability={capability}
        opts={opts}
        set={set}
        transport={selectedTarget?.transport}
      />

      {/* ---- dispatch ---- */}
      <div className="flex flex-wrap items-center gap-3 border-t pt-4">
        <Button onClick={dispatch} disabled={pending || !targetId}>
          <Play />
          {pending ? "下发中…" : "下发任务"}
        </Button>
        <span className="text-muted-foreground text-xs">
          {isLocalTarget
            ? `下发后 Form 将在本机就地运行 agent 并采集 ${CAPABILITY_META[capability].produces}。`
            : `下发后 Form 将远程部署 agent 并采集 ${CAPABILITY_META[capability].produces}。`}
        </span>
      </div>
    </FieldGroup>
  );
}

function CapabilityOptions({
  capability,
  opts,
  set,
  transport,
}: {
  capability: ScanCapability;
  opts: AdminScanOptions;
  set: <K extends keyof AdminScanOptions>(key: K, value: AdminScanOptions[K]) => void;
  transport: ScanTarget["transport"] | undefined;
}) {
  if (capability === "host") {
    return (
      <FieldSet className="rounded-lg border bg-muted/30 p-4">
        <FieldLegend variant="label">主机扫描选项</FieldLegend>
        <Field orientation="vertical">
          <FieldLabel htmlFor="scan-object">扫描对象</FieldLabel>
          <Select
            value={opts.scan_target ?? "all"}
            onValueChange={(value) => set("scan_target", value as string)}
          >
            <SelectTrigger id="scan-object" className="w-full font-mono">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">all · 完整资产报告</SelectItem>
              <SelectItem value="host">host · 仅主机信息</SelectItem>
            </SelectContent>
          </Select>
          <FieldDescription>
            <span className="font-mono">all</span> 以 package 等结构化资产作为规范上传表示。
            CycloneDX SBOM 不作为 Form 报告上传目标；需要 SBOM 时请使用独立 CLI 导出。
          </FieldDescription>
        </Field>
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="malware">
              {transport === "winrm" ? "Microsoft Defender 恶意软件检测" : "恶意文件检测"}
            </FieldLabel>
            <FieldDescription>
              {transport === "winrm"
                ? "复用目标机 Defender，不重复运行 Kcatta 签名引擎；防护状态始终采集，开启后同时读取威胁历史和安全事件。"
                : "使用内置签名及 Form 服务端配置的受管签名库扫描文件（含 EICAR）。"}
            </FieldDescription>
          </FieldContent>
          <Switch
            id="malware"
            checked={opts.malware}
            onCheckedChange={(v) => set("malware", v)}
          />
        </Field>
        {transport === "winrm" && (
          <Field orientation="vertical">
            <FieldLabel htmlFor="windows-defender-scan">Defender 按需扫描模式</FieldLabel>
            <Select
              value={opts.windows_defender_scan}
              onValueChange={(value) =>
                set("windows_defender_scan", value as WindowsDefenderScan)
              }
              disabled={!opts.malware}
            >
              <SelectTrigger id="windows-defender-scan" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">none · 仅采集现有历史，不触发扫描</SelectItem>
                <SelectItem value="quick">quick · 快速扫描（推荐）</SelectItem>
                <SelectItem value="full">full · 全盘扫描</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>
              关闭恶意软件检测时只上报 Defender 运行状态；全盘扫描可能显著延长任务时间。
            </FieldDescription>
          </Field>
        )}
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="posture">安全基线检测</FieldLabel>
            <FieldDescription>检查 SSH、账户口令和危险 SUID/SGID 权限配置。</FieldDescription>
          </FieldContent>
          <Switch
            id="posture"
            checked={opts.posture}
            onCheckedChange={(value) => set("posture", value)}
          />
        </Field>
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="secrets">密钥泄露检测</FieldLabel>
            <FieldDescription>
              显式开启后扫描私钥与常见令牌；只上传指纹和证据，不上传原始密钥。
            </FieldDescription>
          </FieldContent>
          <Switch
            id="secrets"
            checked={opts.secrets}
            onCheckedChange={(value) => set("secrets", value)}
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
            <FieldLabel htmlFor="intel">IOC 威胁情报</FieldLabel>
            <FieldDescription>
              使用 Form 管理的 IOC feed 丰富网络、文件和进程事件并标记命中。
            </FieldDescription>
          </FieldContent>
          <Switch
            id="intel"
            checked={opts.intel}
            onCheckedChange={(value) => set("intel", value)}
          />
        </Field>
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="ebpf">文件 / 进程 eBPF 追踪</FieldLabel>
            <FieldDescription>
              需要 Linux、相应内核权限及带 eBPF 能力的自定义 Agent 构建；不满足时任务会失败。
            </FieldDescription>
          </FieldContent>
          <Switch
            id="ebpf"
            checked={opts.ebpf}
            onCheckedChange={(value) => set("ebpf", value)}
          />
        </Field>
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="pcap">libpcap 深度抓包（自定义构建）</FieldLabel>
            <FieldDescription>
              关闭时仍采集真实 OS 连接表；开启需要 Form 投放带 pcap feature 的 Agent，
              并设置 FORM_TRACE_PCAP_ENABLED=true。
            </FieldDescription>
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
            <FieldLabel htmlFor="duration">采集窗口（秒）</FieldLabel>
            <Input
              id="duration"
              type="number"
              min={1}
              value={opts.duration}
              onChange={(e) => set("duration", Number(e.target.value) || DEFAULTS.duration)}
              className="font-mono"
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
    <FieldSet className="rounded-lg border bg-muted/30 p-4">
      <FieldLegend variant="label">实时防护选项</FieldLegend>
      <div className="text-muted-foreground flex items-start gap-2 text-sm">
        <ShieldAlert className="text-foreground mt-0.5 size-4 shrink-0" />
        <p>
          在目标上启动 <span className="font-mono">agent-respond</span>{" "}
          常驻守护进程，持续把事件推送回 Form。
        </p>
      </div>
      <Field orientation="horizontal">
        <FieldContent>
          <FieldLabel htmlFor="guard-network">网络 IOC / IDS</FieldLabel>
          <FieldDescription>
            监控连接并匹配 Form 管理的 IOC 与轻量 IDS；需要网络采集权限及对应构建能力。
          </FieldDescription>
        </FieldContent>
        <Switch
          id="guard-network"
          checked={opts.guard_network}
          onCheckedChange={(value) => set("guard_network", value)}
        />
      </Field>
      <Field orientation="horizontal">
        <FieldContent>
          <FieldLabel htmlFor="guard-onaccess">文件打开时查毒</FieldLabel>
          <FieldDescription>
            显式开启；需要带 on-access feature 的自定义 Agent 构建和文件系统监控权限。
          </FieldDescription>
        </FieldContent>
        <Switch
          id="guard-onaccess"
          checked={opts.guard_onaccess}
          onCheckedChange={(value) => set("guard_onaccess", value)}
        />
      </Field>
    </FieldSet>
  );
}
