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

  function reset() {
    setName("");
    setAddress("");
    setPort("22");
    setIdentityPath("");
    setPassword("");
  }

  function submit() {
    startTransition(async () => {
      const result = await registerTargetAction({
        name,
        address,
        port: Number(port) || 22,
        transport,
        credential_mode: credMode,
        identity_path: identityPath || null,
        password: password || null,
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
          <FieldLabel htmlFor="t-address">地址（user@host）</FieldLabel>
          <Input
            id="t-address"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="root@10.0.0.9"
            className="font-mono"
          />
        </Field>
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
        <Field>
          <FieldLabel htmlFor="t-transport">传输方式</FieldLabel>
          <Select value={transport} onValueChange={(v) => setTransport(v as Transport)}>
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

        {credMode === "identity" ? (
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
