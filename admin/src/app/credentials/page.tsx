import { KeyRound } from "lucide-react";

import { CredentialsTable } from "@/components/credentials-table";
import { PageHeader } from "@/components/page-header";
import { EmptyState, ErrorState } from "@/components/states";
import { FormApiError, listCredentials } from "@/lib/api";
import type { CredentialInfo } from "@/lib/contracts";

export const dynamic = "force-dynamic";

export default async function CredentialsPage() {
  let credentials: CredentialInfo[] = [];
  let error: FormApiError | null = null;
  try {
    credentials = await listCredentials();
  } catch (err) {
    error =
      err instanceof FormApiError
        ? err
        : new FormApiError(err instanceof Error ? err.message : String(err));
  }

  return (
    <div className="mx-auto w-full max-w-6xl flex-1 p-6 sm:p-8">
      <PageHeader
        title="访问凭证"
        description="管理 Form 主机上为各靶标托管的 SSH 密钥：查看指纹与状态、测试连通、轮换或吊销。密钥始终存放在 Form 主机，绝不下发到浏览器。"
      />

      {error ? (
        <ErrorState message={error.message} />
      ) : credentials.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="尚无可管理的凭证"
          description="为 SSH 靶标注册并引导托管密钥后，凭证会在此列出。本机（local）目标无需凭据，不会出现在这里。"
        />
      ) : (
        <CredentialsTable credentials={credentials} />
      )}
    </div>
  );
}
