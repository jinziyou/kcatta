import {
  Box,
  Bug,
  ChevronRight,
  Database,
  Key,
  Layers,
  Network,
  Package as PackageIcon,
  Plug,
  Server,
  User,
} from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { CopyableId } from "@/components/copy-button";
import { SeverityBadge } from "@/components/severity-badge";
import { EmptyState } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AnalyzerApiError, getAssetReport } from "@/lib/api";
import type {
  Account,
  AssetKind,
  Container,
  AssetReport,
  Credential,
  Image,
  Package,
  Port,
  Service,
  Vulnerability,
} from "@/lib/contracts";
import { fmtTimestampFull, shortId } from "@/lib/format";
import { SEVERITY_RANK } from "@/lib/meta";

import type { LucideIcon } from "lucide-react";

export const dynamic = "force-dynamic";

const KIND_META: Record<AssetKind, { label: string; icon: LucideIcon }> = {
  package: { label: "软件包", icon: PackageIcon },
  service: { label: "服务", icon: Plug },
  port: { label: "监听端口", icon: Network },
  account: { label: "账号", icon: User },
  credential: { label: "凭据", icon: Key },
  container: { label: "容器", icon: Box },
  image: { label: "镜像", icon: Layers },
};

const EM_DASH = "—";

/** Render an optional cell value, falling back to a muted dash when absent. */
function orDash(value: string | number | null | undefined) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted-foreground">{EM_DASH}</span>;
  }
  return value;
}

/** Label/value pair rendered in the host info grid. */
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-muted-foreground text-xs">{label}</span>
      <span className="text-sm">{children}</span>
    </div>
  );
}

/** Section wrapper: icon + label + count header above a bordered table. */
function AssetSection({
  kind,
  count,
  children,
}: {
  kind: AssetKind;
  count: number;
  children: React.ReactNode;
}) {
  const { label, icon: Icon } = KIND_META[kind];
  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <Icon className="text-muted-foreground size-4" />
        <h2 className="text-sm font-semibold">{label}</h2>
        <span className="text-muted-foreground text-xs tabular-nums">{count}</span>
      </div>
      <div className="overflow-hidden rounded-lg border">
        <Table>{children}</Table>
      </div>
    </section>
  );
}

function ReportDetail({ report }: { report: AssetReport }) {
  const host = report.host;
  const assets = report.assets ?? [];

  const packages: Package[] = [];
  const services: Service[] = [];
  const ports: Port[] = [];
  const accounts: Account[] = [];
  const credentials: Credential[] = [];
  const containers: Container[] = [];
  const images: Image[] = [];
  for (const asset of assets) {
    switch (asset.kind) {
      case "package":
        packages.push(asset);
        break;
      case "service":
        services.push(asset);
        break;
      case "port":
        ports.push(asset);
        break;
      case "account":
        accounts.push(asset);
        break;
      case "credential":
        credentials.push(asset);
        break;
      case "container":
        containers.push(asset);
        break;
      case "image":
        images.push(asset);
        break;
    }
  }

  const vulns = [...(report.vulnerabilities ?? [])].sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;
    return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
  });

  return (
    <div className="flex flex-col gap-8">
      {/* host info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            <Server className="text-muted-foreground size-4" />
            <span className="font-mono text-base">{host.hostname}</span>
            <Badge variant="secondary">{host.os}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="主机 ID">
            <CopyableId value={host.host_id} />
          </Field>
          <Field label="报告 ID">
            <CopyableId value={report.report_id} />
          </Field>
          <Field label="采集时间">
            <span className="font-mono text-xs">{fmtTimestampFull(report.collected_at)}</span>
          </Field>
          <Field label="采集器版本">
            <span className="font-mono text-xs">{orDash(report.scanner_version)}</span>
          </Field>
          <Field label="IP 地址">
            <span className="font-mono text-xs">
              {host.ip_addrs && host.ip_addrs.length > 0 ? host.ip_addrs.join(", ") : EM_DASH}
            </span>
          </Field>
          <Field label="内核">
            <span className="font-mono text-xs">{orDash(host.kernel)}</span>
          </Field>
          <Field label="架构">
            <span className="font-mono text-xs">{orDash(host.arch)}</span>
          </Field>
          {host.mac_addrs && host.mac_addrs.length > 0 && (
            <Field label="MAC 地址">
              <span className="font-mono text-xs">{host.mac_addrs.join(", ")}</span>
            </Field>
          )}
        </CardContent>
      </Card>

      {/* packages */}
      {packages.length > 0 && (
        <AssetSection kind="package" count={packages.length}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>名称</TableHead>
              <TableHead>版本</TableHead>
              <TableHead className="hidden sm:table-cell">来源</TableHead>
              <TableHead className="hidden md:table-cell">生态</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {packages.map((pkg) => (
              <TableRow key={pkg.asset_id}>
                <TableCell className="font-mono text-xs font-medium">{pkg.name}</TableCell>
                <TableCell className="font-mono text-xs">{orDash(pkg.version)}</TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  {orDash(pkg.source)}
                </TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">
                  {orDash(pkg.ecosystem)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {containers.length > 0 && (
        <AssetSection kind="container" count={containers.length}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>名称</TableHead>
              <TableHead>运行时</TableHead>
              <TableHead className="hidden sm:table-cell">镜像</TableHead>
              <TableHead className="hidden md:table-cell">状态</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {containers.map((ctr) => (
              <TableRow key={ctr.asset_id}>
                <TableCell className="font-mono text-xs font-medium">{ctr.name}</TableCell>
                <TableCell>
                  <Badge variant="outline">{ctr.runtime}</Badge>
                </TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  {orDash(ctr.image)}
                </TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">
                  {orDash(ctr.status)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {images.length > 0 && (
        <AssetSection kind="image" count={images.length}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>名称</TableHead>
              <TableHead>运行时</TableHead>
              <TableHead className="hidden sm:table-cell">镜像 ID</TableHead>
              <TableHead className="hidden md:table-cell">标签</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {images.map((img) => (
              <TableRow key={img.asset_id}>
                <TableCell className="font-mono text-xs font-medium">{img.name}</TableCell>
                <TableCell>
                  <Badge variant="outline">{img.runtime}</Badge>
                </TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  {orDash(img.image_id ? shortId(img.image_id) : null)}
                </TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">
                  {img.tags && img.tags.length > 0 ? img.tags.join(", ") : EM_DASH}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {/* services */}
      {services.length > 0 && (
        <AssetSection kind="service" count={services.length}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>名称</TableHead>
              <TableHead>状态</TableHead>
              <TableHead className="hidden sm:table-cell">可执行路径</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {services.map((svc) => (
              <TableRow key={svc.asset_id}>
                <TableCell className="font-mono text-xs font-medium">{svc.name}</TableCell>
                <TableCell>
                  <Badge variant="outline">{svc.status}</Badge>
                </TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  {orDash(svc.exec_path)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {/* ports */}
      {ports.length > 0 && (
        <AssetSection kind="port" count={ports.length}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>协议 / 端口</TableHead>
              <TableHead>监听地址</TableHead>
              <TableHead className="hidden sm:table-cell">进程</TableHead>
              <TableHead className="hidden md:table-cell">PID</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {ports.map((port) => (
              <TableRow key={port.asset_id}>
                <TableCell className="font-mono text-xs font-medium">
                  {port.proto}/{port.port}
                </TableCell>
                <TableCell className="font-mono text-xs">{orDash(port.listen_addr)}</TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  {orDash(port.process_name)}
                </TableCell>
                <TableCell className="hidden font-mono text-xs tabular-nums md:table-cell">
                  {orDash(port.pid)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {/* accounts */}
      {accounts.length > 0 && (
        <AssetSection kind="account" count={accounts.length}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>用户名</TableHead>
              <TableHead>UID</TableHead>
              <TableHead className="hidden sm:table-cell">Shell</TableHead>
              <TableHead className="hidden md:table-cell">最近登录</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {accounts.map((acct) => (
              <TableRow key={acct.asset_id}>
                <TableCell className="font-mono text-xs font-medium">{acct.username}</TableCell>
                <TableCell className="font-mono text-xs tabular-nums">{orDash(acct.uid)}</TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  {orDash(acct.shell)}
                </TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">
                  {orDash(acct.last_login)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {/* credentials */}
      {credentials.length > 0 && (
        <AssetSection kind="credential" count={credentials.length}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>类型</TableHead>
              <TableHead>指纹</TableHead>
              <TableHead className="hidden sm:table-cell">归属</TableHead>
              <TableHead className="hidden md:table-cell">路径</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {credentials.map((cred) => (
              <TableRow key={cred.asset_id}>
                <TableCell>
                  <Badge variant="outline">{cred.credential_kind}</Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">{shortId(cred.fingerprint, 16)}</TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  {orDash(cred.owner)}
                </TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">
                  {orDash(cred.path)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {assets.length === 0 && (
        <EmptyState
          icon={Database}
          title="未采集到资产"
          description="本次采集没有发现可上报的资产清单。"
        />
      )}

      {/* vulnerabilities */}
      <section className="flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <Bug className="text-muted-foreground size-4" />
          <h2 className="text-sm font-semibold">漏洞发现</h2>
          <span className="text-muted-foreground text-xs tabular-nums">{vulns.length}</span>
        </div>
        {vulns.length === 0 ? (
          <EmptyState
            icon={Bug}
            title="未发现漏洞"
            description="检测引擎未在该报告的资产上匹配到任何漏洞。"
          />
        ) : (
          <div className="flex flex-col gap-2">
            {vulns.map((v: Vulnerability) => (
              <Card key={`${v.vuln_id}:${v.affected_asset_id}`} size="sm" className="gap-2 p-4">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                  <SeverityBadge severity={v.severity} />
                  <span className="font-mono text-sm font-medium">{v.vuln_id}</span>
                  <span className="text-muted-foreground text-xs">来源 {v.source}</span>
                  {v.cvss_score != null && (
                    <Badge variant="outline" className="tabular-nums">
                      CVSS {v.cvss_score}
                    </Badge>
                  )}
                  <span className="text-muted-foreground ml-auto font-mono text-xs">
                    {v.affected_asset_id}
                  </span>
                </div>
                {v.evidence && <p className="text-muted-foreground text-xs">{v.evidence}</p>}
              </Card>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

export default async function ReportPage({
  params,
}: {
  params: Promise<{ reportId: string }>;
}) {
  const { reportId } = await params;

  let report: AssetReport;
  try {
    report = await getAssetReport(reportId);
  } catch (err) {
    if (err instanceof AnalyzerApiError && err.status === 404) {
      notFound();
    }
    throw err;
  }

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-8">
      <nav className="text-muted-foreground mb-6 flex items-center gap-1 text-sm">
        <Link href="/reports" className="hover:text-foreground">
          资产报告
        </Link>
        <ChevronRight className="size-4" />
        <span className="text-foreground font-mono">{report.host.hostname}</span>
      </nav>
      <ReportDetail report={report} />
    </div>
  );
}
