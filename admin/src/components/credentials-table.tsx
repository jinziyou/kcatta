"use client";

import { KeyRound, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { toast } from "sonner";

import {
  revokeCredentialAction,
  rotateCredentialAction,
  testCredentialAction,
} from "@/app/credentials/actions";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { CredentialInfo } from "@/lib/contracts";

type Action = "rotate" | "revoke";
interface Confirm {
  id: string;
  action: Action;
}

/** Managed-key lifecycle table: test connectivity, rotate, revoke. */
export function CredentialsTable({ credentials }: { credentials: CredentialInfo[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [password, setPassword] = useState("");

  function closeConfirm() {
    setConfirm(null);
    setPassword("");
  }

  function runTest(cred: CredentialInfo) {
    startTransition(async () => {
      const r = await testCredentialAction(cred.credential_id);
      if (!r.ok) {
        toast.error("测试失败", { description: r.error });
      } else if (r.reachable) {
        toast.success("连通正常", { description: r.detail });
      } else {
        toast.warning("无法连通", { description: r.detail });
      }
    });
  }

  function runConfirmed() {
    if (!confirm) return;
    const { id, action } = confirm;
    const pw = password || null;
    startTransition(async () => {
      const r =
        action === "rotate"
          ? await rotateCredentialAction(id, pw)
          : await revokeCredentialAction(id, pw);
      if (r.ok) {
        toast.success(action === "rotate" ? "已轮换密钥" : "已吊销凭证", { description: r.detail });
        closeConfirm();
        router.refresh();
      } else {
        toast.error(action === "rotate" ? "轮换失败" : "吊销失败", { description: r.error });
      }
    });
  }

  return (
    <div className="overflow-hidden rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/40 hover:bg-muted/40">
            <TableHead>地址</TableHead>
            <TableHead className="hidden md:table-cell">指纹</TableHead>
            <TableHead className="hidden lg:table-cell">引用靶标</TableHead>
            <TableHead>状态</TableHead>
            <TableHead className="w-px text-right">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {credentials.map((cred) => {
            const managed = cred.credential_mode === "managed_key";
            const open = confirm?.id === cred.credential_id;
            return (
              <Row
                key={cred.credential_id}
                cred={cred}
                managed={managed}
                open={open}
                confirm={open ? confirm : null}
                pending={pending}
                password={password}
                setPassword={setPassword}
                onTest={() => runTest(cred)}
                onStage={(action) => {
                  setPassword("");
                  setConfirm({ id: cred.credential_id, action });
                }}
                onCancel={closeConfirm}
                onConfirm={runConfirmed}
              />
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

function Row({
  cred,
  managed,
  open,
  confirm,
  pending,
  password,
  setPassword,
  onTest,
  onStage,
  onCancel,
  onConfirm,
}: {
  cred: CredentialInfo;
  managed: boolean;
  open: boolean;
  confirm: Confirm | null;
  pending: boolean;
  password: string;
  setPassword: (v: string) => void;
  onTest: () => void;
  onStage: (action: Action) => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const isWinrm = cred.transport === "winrm";
  const credLabel =
    cred.credential_mode === "identity" ? "identity" : isWinrm ? "客户端证书" : "托管密钥";
  // WinRM cert rotation has no key-reuse path — the account password is required.
  const winrmRotateNeedsPw = isWinrm && confirm?.action === "rotate" && !password;
  return (
    <>
      <TableRow>
        <TableCell>
          <div className="flex items-center gap-2">
            <KeyRound className="text-muted-foreground size-4 shrink-0" />
            <span className="font-mono text-xs">
              {cred.address}:{cred.port}
            </span>
            <Badge variant="secondary" className="hidden sm:inline-flex">
              {cred.transport.toUpperCase()}
            </Badge>
            <Badge variant="outline" className="hidden sm:inline-flex">
              {credLabel}
            </Badge>
          </div>
        </TableCell>
        <TableCell className="text-muted-foreground hidden font-mono text-xs md:table-cell">
          {cred.fingerprint ?? "—"}
        </TableCell>
        <TableCell className="text-muted-foreground hidden text-xs lg:table-cell">
          {cred.target_names.join("、")}
          <span className="ml-1">（{cred.target_ids.length}）</span>
        </TableCell>
        <TableCell>
          <Badge variant={cred.exists ? "secondary" : "outline"}>
            {cred.exists ? "已就绪" : "缺失"}
          </Badge>
        </TableCell>
        <TableCell className="text-right">
          <div className="flex items-center justify-end gap-1">
            <Button size="xs" variant="ghost" onClick={onTest} disabled={pending}>
              <ShieldCheck />
              测试
            </Button>
            <Button
              size="xs"
              variant="ghost"
              onClick={() => onStage("rotate")}
              disabled={pending || !managed}
              title={managed ? undefined : "identity 凭证由运维在 Form 主机外部管理"}
            >
              <RefreshCw />
              轮换
            </Button>
            <Button
              size="xs"
              variant="ghost"
              className="text-destructive hover:text-destructive"
              onClick={() => onStage("revoke")}
              disabled={pending || !managed}
              title={managed ? undefined : "identity 凭证由运维在 Form 主机外部管理"}
            >
              <Trash2 />
              吊销
            </Button>
          </div>
        </TableCell>
      </TableRow>
      {open && confirm && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell colSpan={5}>
            <div className="flex flex-col gap-3 py-1">
              <p className="text-sm">
                {confirm.action === "rotate" ? (
                  isWinrm ? (
                    <>
                      将为 <span className="font-mono">{cred.address}</span>{" "}
                      生成新的客户端证书并重新创建 ClientCertificate 映射（需目标账户口令），替换旧证书。
                    </>
                  ) : (
                    <>
                      将为 <span className="font-mono">{cred.address}</span>{" "}
                      生成新的托管密钥并安装、验证后替换旧密钥。旧密钥仍可用时无需密码。
                    </>
                  )
                ) : isWinrm ? (
                  <>
                    将移除 <span className="font-mono">{cred.address}</span> 上的 ClientCertificate
                    映射并删除 Form 主机上的本地证书。
                    <span className="text-destructive">
                      {" "}
                      引用此凭证的靶标在重新注册引导前将无法扫描。
                    </span>
                  </>
                ) : (
                  <>
                    将从 <span className="font-mono">{cred.address}</span> 的 authorized_keys
                    移除该密钥并删除 Form 主机上的本地密钥文件。
                    <span className="text-destructive">
                      {" "}
                      引用此凭证的靶标在重新注册引导前将无法扫描。
                    </span>
                  </>
                )}
              </p>
              <div className="flex flex-wrap items-end gap-2">
                <div className="flex flex-col gap-1">
                  <label htmlFor="cred-pw" className="text-muted-foreground text-xs">
                    {winrmRotateNeedsPw
                      ? "目标账户口令（WinRM 轮换必填，不会落盘）"
                      : "一次性密码（旧凭证已失效时才需要，不会落盘）"}
                  </label>
                  <Input
                    id="cred-pw"
                    type="password"
                    autoComplete="off"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="h-8 w-64"
                    placeholder={winrmRotateNeedsPw ? "必填" : "可留空"}
                  />
                </div>
                <Button
                  size="sm"
                  variant={confirm.action === "revoke" ? "destructive" : "default"}
                  onClick={onConfirm}
                  disabled={pending || winrmRotateNeedsPw}
                >
                  {pending ? "执行中…" : confirm.action === "rotate" ? "确认轮换" : "确认吊销"}
                </Button>
                <Button size="sm" variant="ghost" onClick={onCancel} disabled={pending}>
                  取消
                </Button>
              </div>
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}
