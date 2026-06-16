"use client";

import { Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { toast } from "sonner";

import { registerTargetAction } from "@/app/targets/actions";
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
import type { CredentialMode, Transport } from "@/lib/contracts";

const TRANSPORTS: { value: Transport; label: string }[] = [
  { value: "ssh", label: "SSH" },
  { value: "winrm", label: "WinRM" },
  { value: "local", label: "本机（analyzer 主机，无需 SSH）" },
];

const CRED_MODES: { value: CredentialMode; label: string }[] = [
  { value: "managed_key", label: "托管密钥（通过一次性密码引导）" },
  { value: "identity", label: "服务端密钥路径（identity）" },
];

export function RegisterTargetForm() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("22");
  const [transport, setTransport] = useState<Transport>("ssh");
  const [credMode, setCredMode] = useState<CredentialMode>("managed_key");
  const [identityPath, setIdentityPath] = useState("");
  const [password, setPassword] = useState("");

  // transport=local 表示 analyzer 主机自身（就地扫描，无 SSH）——无端口/凭据。
  const isLocal = transport === "local";

  function onTransportChange(v: Transport) {
    setTransport(v);
    if (v === "local") {
      if (!address) setAddress("localhost");
      setPassword("");
    } else if (address === "localhost") {
      // Don't leak the local placeholder into an ssh/winrm registration.
      setAddress("");
    }
  }

  function reset() {
    setName("");
    // Keep the form usable for another local registration (auto-fill only re-fires
    // on transport change, not on reset).
    setAddress(transport === "local" ? "localhost" : "");
    setPort("22");
    setIdentityPath("");
    setPassword("");
  }

  function submit() {
    startTransition(async () => {
      const result = await registerTargetAction({
        name,
        address,
        // 本机目标无 SSH 连接信息：端口/凭据交由后端忽略，且不下发任何密码。
        port: Number(port) || 22,
        transport,
        credential_mode: isLocal ? undefined : credMode,
        identity_path: isLocal ? null : identityPath || null,
        password: isLocal ? null : password || null,
      });
      if (result.ok) {
        toast.success("目标已注册", { description: `${name} · ${address}` });
        reset();
        router.refresh();
      } else {
        toast.error("注册失败", { description: result.error });
      }
    });
  }

  return (
    <FieldGroup>
      <div className="grid gap-5 sm:grid-cols-2">
        <Field>
          <FieldLabel htmlFor="t-name">名称</FieldLabel>
          <Input id="t-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="db-01" />
        </Field>
        <Field>
          <FieldLabel htmlFor="t-address">{isLocal ? "标签" : "地址（user@host）"}</FieldLabel>
          <Input
            id="t-address"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder={isLocal ? "localhost" : "root@10.0.0.9"}
            className="font-mono"
          />
          {isLocal && (
            <FieldDescription>本机扫描无需连接信息，地址仅作展示标签。</FieldDescription>
          )}
        </Field>
        {!isLocal && (
          <Field>
            <FieldLabel htmlFor="t-port">端口</FieldLabel>
            <Input
              id="t-port"
              type="number"
              min={1}
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className="font-mono"
            />
          </Field>
        )}
        <Field>
          <FieldLabel htmlFor="t-transport">传输方式</FieldLabel>
          <Select value={transport} onValueChange={(v) => onTransportChange(v as Transport)}>
            <SelectTrigger id="t-transport" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TRANSPORTS.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>

        {isLocal ? (
          <Field className="sm:col-span-2">
            <FieldDescription>
              将在 <strong>analyzer 主机自身</strong>就地运行 agent-host 采集（host 能力），
              无需 SSH 凭据。容器化部署时，需把宿主机根目录挂载进 analyzer 容器并设置{" "}
              <span className="font-mono">ANALYZER_LOCAL_SCAN_ROOT</span> 指向挂载点，否则扫描的是容器自身。
            </FieldDescription>
          </Field>
        ) : (
          <Field className="sm:col-span-2">
            <FieldLabel htmlFor="t-cred">凭据模式</FieldLabel>
            <Select value={credMode} onValueChange={(v) => setCredMode(v as CredentialMode)}>
              <SelectTrigger id="t-cred" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CRED_MODES.map((m) => (
                  <SelectItem key={m.value} value={m.value}>
                    {m.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        )}

        {isLocal ? null : credMode === "identity" ? (
          <Field className="sm:col-span-2">
            <FieldLabel htmlFor="t-identity">密钥路径</FieldLabel>
            <Input
              id="t-identity"
              value={identityPath}
              onChange={(e) => setIdentityPath(e.target.value)}
              placeholder="/home/analyzer/.ssh/id_ed25519"
              className="font-mono"
            />
            <FieldDescription>analyzer 主机上的私钥文件路径。</FieldDescription>
          </Field>
        ) : (
          <Field className="sm:col-span-2">
            <FieldLabel htmlFor="t-password">一次性密码</FieldLabel>
            <Input
              id="t-password"
              type="password"
              autoComplete="off"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <FieldDescription>
              仅用于在 analyzer 主机上引导托管 SSH 密钥，<strong>不会被持久化存储</strong>。
            </FieldDescription>
          </Field>
        )}
      </div>

      <div className="flex items-center gap-3 border-t pt-4">
        <Button onClick={submit} disabled={pending || !name || !address}>
          <Plus />
          {pending ? "注册中…" : "注册目标"}
        </Button>
      </div>
    </FieldGroup>
  );
}
