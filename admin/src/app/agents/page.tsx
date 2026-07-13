import { Fingerprint } from "lucide-react";

import { AgentIdentitiesTable } from "@/components/agent-identities-table";
import { PageHeader } from "@/components/page-header";
import { EmptyState, ErrorState } from "@/components/states";
import { FormApiError, listAgentIdentities } from "@/lib/api";
import type { AgentIdentity } from "@/lib/contracts";

export const dynamic = "force-dynamic";

export default async function AgentsPage() {
  let identities: AgentIdentity[] = [];
  let error: FormApiError | null = null;
  try {
    identities = await listAgentIdentities();
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  return (
    <div className="mx-auto w-full max-w-7xl flex-1 p-6 sm:p-8">
      <PageHeader
        eyebrow="扫描中心 / 身份注册表"
        title="Agent 身份"
        description="只读查看 Agent 与靶标、主机、上报权限及 mTLS 证书代次的绑定；此处仅允许吊销整个身份。吊销不可逆并会立即阻断上报。签发和轮换会产生一次性私钥 bundle，因此刻意不在浏览器界面提供。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : identities.length === 0 ? (
        <EmptyState
          icon={Fingerprint}
          title="尚无 Agent 身份"
          description="Agent 身份由 Form 在部署边界签发。完成靶标部署后，这里只会展示非秘密身份与证书元数据。"
        />
      ) : (
        <AgentIdentitiesTable identities={identities} />
      )}
    </div>
  );
}
