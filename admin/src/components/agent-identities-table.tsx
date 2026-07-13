"use client";

import { Fingerprint, ShieldOff } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { toast } from "sonner";

import { revokeAgentIdentityAction } from "@/app/agents/actions";
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
import type {
  AgentCertificate,
  AgentCertificateState,
  AgentIdentity,
  AgentScope,
} from "@/lib/contracts";
import { fmtTimestampFull } from "@/lib/format";

const SCOPE_LABEL: Record<AgentScope, string> = {
  "asset-report": "资产上报",
  "trace-batch": "网络追踪",
  "guard-event": "防护事件",
};

const CERTIFICATE_STATE_LABEL: Record<AgentCertificateState, string> = {
  staged: "待激活",
  active: "生效中",
  retired: "已退役",
  revoked: "已吊销",
};

/** Read-only identity registry with one deliberately narrow destructive action. */
export function AgentIdentitiesTable({ identities }: { identities: AgentIdentity[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [confirmAgentId, setConfirmAgentId] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState("");

  function closeConfirm() {
    setConfirmAgentId(null);
    setConfirmation("");
  }

  function stageRevoke(agentId: string) {
    setConfirmAgentId(agentId);
    setConfirmation("");
  }

  function runRevoke() {
    if (!confirmAgentId || confirmation !== confirmAgentId) return;
    const agentId = confirmAgentId;
    startTransition(async () => {
      const result = await revokeAgentIdentityAction(agentId);
      if (result.ok) {
        toast.success("Agent 整身份已吊销", { description: result.detail });
        closeConfirm();
        router.refresh();
      } else {
        toast.error("吊销失败", { description: result.error });
      }
    });
  }

  return (
    <div className="overflow-hidden rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/40 hover:bg-muted/40">
            <TableHead>Agent ID</TableHead>
            <TableHead>Target ID</TableHead>
            <TableHead>Canonical Host ID</TableHead>
            <TableHead>Scopes</TableHead>
            <TableHead>身份状态</TableHead>
            <TableHead>Generation</TableHead>
            <TableHead>证书状态 / 到期时间</TableHead>
            <TableHead className="w-px text-right">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {identities.map((identity) => {
            const open = confirmAgentId === identity.agent_id;
            return (
              <IdentityRows
                key={identity.agent_id}
                identity={identity}
                open={open}
                pending={pending}
                confirmation={open ? confirmation : ""}
                onConfirmationChange={setConfirmation}
                onStage={() => stageRevoke(identity.agent_id)}
                onCancel={closeConfirm}
                onConfirm={runRevoke}
              />
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

function IdentityRows({
  identity,
  open,
  pending,
  confirmation,
  onConfirmationChange,
  onStage,
  onCancel,
  onConfirm,
}: {
  identity: AgentIdentity;
  open: boolean;
  pending: boolean;
  confirmation: string;
  onConfirmationChange: (value: string) => void;
  onStage: () => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const revoked = identity.state === "revoked";
  const confirmationId = "revoke-agent-" + identity.agent_id;

  return (
    <>
      <TableRow aria-expanded={open}>
        <TableCell className="max-w-52 whitespace-normal">
          <span className="flex items-start gap-2 font-mono text-xs break-all">
            <Fingerprint className="text-muted-foreground mt-0.5 size-4 shrink-0" />
            {identity.agent_id}
          </span>
        </TableCell>
        <TableCell className="max-w-48 font-mono text-xs whitespace-normal break-all">
          {identity.target_id}
        </TableCell>
        <TableCell className="max-w-52 font-mono text-xs whitespace-normal break-all">
          {identity.canonical_host_id}
        </TableCell>
        <TableCell className="max-w-48 whitespace-normal">
          <div className="flex flex-wrap gap-1">
            {identity.scopes.map((scope) => (
              <Badge key={scope} variant="outline">
                {SCOPE_LABEL[scope]}
              </Badge>
            ))}
          </div>
        </TableCell>
        <TableCell>
          <Badge variant={revoked ? "destructive" : "secondary"}>
            {revoked ? "已吊销" : "生效中"}
          </Badge>
        </TableCell>
        <TableCell className="font-mono text-xs">G{identity.generation}</TableCell>
        <TableCell className="min-w-72 whitespace-normal">
          <CertificateList certificates={identity.certificates} />
        </TableCell>
        <TableCell className="text-right">
          <Button
            size="xs"
            variant="ghost"
            className="text-destructive hover:text-destructive"
            onClick={onStage}
            disabled={pending || revoked}
            aria-expanded={open}
            title={revoked ? "该 Agent 身份已吊销" : "不可逆地吊销整个 Agent 身份"}
          >
            <ShieldOff />
            {revoked ? "已吊销" : "吊销整身份"}
          </Button>
        </TableCell>
      </TableRow>

      {open && !revoked && (
        <TableRow className="bg-destructive/5 hover:bg-destructive/5">
          <TableCell colSpan={8} className="whitespace-normal">
            <div className="flex max-w-3xl flex-col gap-3 py-2">
              <div className="space-y-1 text-sm">
                <p className="text-destructive font-medium">此操作不可逆。</p>
                <p>
                  将吊销 Agent <span className="font-mono">{identity.agent_id}</span>{" "}
                  及其所有 active、staged、retired 证书代次，并立即阻断资产、追踪和防护事件上报。恢复上报需要在浏览器之外重新签发并部署新身份。
                </p>
              </div>
              <div className="flex flex-wrap items-end gap-2">
                <div className="flex min-w-72 flex-1 flex-col gap-1">
                  <label htmlFor={confirmationId} className="text-muted-foreground text-xs">
                    输入完整 Agent ID 以确认吊销整身份
                  </label>
                  <Input
                    id={confirmationId}
                    value={confirmation}
                    onChange={(event) => onConfirmationChange(event.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    className="h-8 font-mono"
                    placeholder={identity.agent_id}
                    disabled={pending}
                  />
                </div>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={onConfirm}
                  disabled={pending || confirmation !== identity.agent_id}
                >
                  {pending ? "吊销中…" : "确认永久吊销"}
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

function CertificateList({ certificates }: { certificates: AgentCertificate[] }) {
  if (certificates.length === 0) {
    return <span className="text-muted-foreground text-xs">尚无证书</span>;
  }

  const ordered = [...certificates].sort((a, b) => b.generation - a.generation);
  return (
    <div className="flex flex-col gap-1.5">
      {ordered.map((certificate) => (
        <div
          key={certificate.agent_id + "-" + certificate.generation}
          className="flex flex-wrap items-center gap-x-2 gap-y-1"
        >
          <Badge variant={certificate.state === "revoked" ? "destructive" : "outline"}>
            G{certificate.generation} · {CERTIFICATE_STATE_LABEL[certificate.state]}
          </Badge>
          <time
            dateTime={certificate.not_after}
            className="text-muted-foreground font-mono text-xs"
          >
            到期 {fmtTimestampFull(certificate.not_after)}
          </time>
        </div>
      ))}
    </div>
  );
}
