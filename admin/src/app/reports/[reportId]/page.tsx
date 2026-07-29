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
  ShieldCheck,
  User,
} from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { CopyableId } from "@/components/copy-button";
import { CoverageMatrix } from "@/components/coverage-matrix";
import { PageNav } from "@/components/page-nav";
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
import {
  FormApiError,
  getReportDetailPage,
} from "@/lib/api";
import type { LineageSummary, ReportDetailPage } from "@/lib/api";
import type {
  Account,
  AssetKind,
  Container,
  AssetReport,
  Credential,
  DetectionResult,
  Image,
  Package,
  Port,
  Service,
  SecurityProduct,
  Vulnerability,
} from "@/lib/contracts";
import {
  DETECTION_STATUS_LABEL,
  detectionCoverage,
  detectionReasonLabel,
  detectionRecordComplete,
  mergeDetectionCoverage,
} from "@/lib/detection";
import { fmtTimestampFull } from "@/lib/format";
import { parsePage } from "@/lib/pagination";

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
  security_product: { label: "安全产品", icon: ShieldCheck },
};

const EM_DASH = "—";
const ASSET_PAGE_SIZE = 50;
const FINDING_PAGE_SIZE = 50;
const MAX_DETAIL_PAGE = 1_000_000;
const ASSET_KIND_ORDER: AssetKind[] = [
  "security_product",
  "service",
  "port",
  "account",
  "credential",
  "container",
  "image",
  "package",
];
function reportPageHref(
  reportId: string,
  assetPage: number,
  findingPage: number,
  anchor: "assets" | "findings",
): string {
  const params = new URLSearchParams();
  if (assetPage > 0) params.set("assets_page", String(assetPage));
  if (findingPage > 0) params.set("findings_page", String(findingPage));
  const query = params.toString();
  return `/reports/${encodeURIComponent(reportId)}${query ? `?${query}` : ""}#${anchor}`;
}

/** Render an optional cell value, falling back to a muted dash when absent. */
function orDash(value: string | number | null | undefined) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted-foreground">{EM_DASH}</span>;
  }
  return value;
}

function enabledLabel(value: boolean | null | undefined) {
  if (value === null || value === undefined) return EM_DASH;
  return value ? "开启" : "关闭";
}

const SECURITY_STATUS_LABEL: Record<SecurityProduct["status"], string> = {
  active: "主动防护",
  passive: "被动模式",
  disabled: "已禁用",
  unavailable: "不可用",
};

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
  total,
  children,
}: {
  kind: AssetKind;
  count: number;
  total: number;
  children: React.ReactNode;
}) {
  const { label, icon: Icon } = KIND_META[kind];
  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <Icon className="text-muted-foreground size-4" />
        <h2 className="text-sm font-semibold">{label}</h2>
        <span className="text-muted-foreground text-xs tabular-nums">
          {count === total ? total : `本页 ${count} / 共 ${total}`}
        </span>
      </div>
      <div className="overflow-hidden rounded-lg border">
        <Table>{children}</Table>
      </div>
    </section>
  );
}

type DetectionState =
  | { status: "found"; lineage: LineageSummary & { records: DetectionResult[] } }
  | { status: "missing" }
  | { status: "error" };

function ReportDetail({
  report,
  assetLineage,
  detection,
  assetTotal,
  assetKindTotals,
  assetPage,
  assetHasMore,
  vulnerabilities,
  vulnerabilityTotal,
  findingPage,
  findingPageSize,
  findingHasMore,
}: {
  report: AssetReport;
  assetLineage: LineageSummary;
  detection: DetectionState;
  assetTotal: number;
  assetKindTotals: Record<string, number>;
  assetPage: number;
  assetHasMore: boolean;
  vulnerabilities: Vulnerability[];
  vulnerabilityTotal: number;
  findingPage: number;
  findingPageSize: number;
  findingHasMore: boolean;
}) {
  const host = report.host;
  const visibleAssets = report.assets ?? [];

  const packages: Package[] = [];
  const services: Service[] = [];
  const ports: Port[] = [];
  const accounts: Account[] = [];
  const credentials: Credential[] = [];
  const containers: Container[] = [];
  const images: Image[] = [];
  const securityProducts: SecurityProduct[] = [];
  for (const asset of visibleAssets) {
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
      case "security_product":
        securityProducts.push(asset);
        break;
    }
  }

  const vulns = vulnerabilities;
  const findingStart = findingPage * findingPageSize;
  const detectionCoverages =
    detection.status === "found"
      ? detection.lineage.records.map(detectionCoverage)
      : [];
  const coverageMatrix =
    detection.status === "found" ? mergeDetectionCoverage(detection.lineage.records) : [];
  const detectionVerified =
    assetLineage.complete === true &&
    detection.status === "found" &&
    detection.lineage.complete === true &&
    detection.lineage.records.length > 0 &&
    detection.lineage.records.every(detectionRecordComplete);
  const detectionStatuses = [...new Set(detectionCoverages.map((coverage) => coverage.status))];
  const scannedPackages = detectionCoverages.reduce(
    (count, coverage) => count + coverage.scannedPackages,
    0,
  );
  const unresolvedPackages = detectionCoverages.reduce(
    (count, coverage) => count + coverage.unresolvedPackages,
    0,
  );
  const uncoveredPackages = detectionCoverages.reduce(
    (count, coverage) => count + coverage.uncoveredPackages,
    0,
  );
  const truncationReasons = [
    ...new Set(
      detectionCoverages
        .filter((coverage) => coverage.truncated)
        .map((coverage) => coverage.truncationReason ?? "limit_reached"),
    ),
  ];
  const coverageReasons = [
    ...new Set(
      detectionCoverages
        .map((coverage) => coverage.reason)
        .filter((reason): reason is string => Boolean(reason)),
    ),
  ];

  return (
    <div className="flex flex-col gap-8">
      {/* host info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            <Server className="text-muted-foreground size-4" />
            <span className="font-mono text-base">{host.hostname}</span>
            <Badge variant="secondary">{host.os}</Badge>
            <Badge
              variant={assetLineage.complete === false ? "destructive" : "outline"}
              title={
                assetLineage.complete === null
                  ? "上报 ID 未声明分片总数，无法证明所有分片均已收到"
                  : undefined
              }
            >
              上传分片 {assetLineage.received_chunks}/
              {assetLineage.expected_chunks ?? "?"}
              {assetLineage.complete === true
                ? " · 完整"
                : assetLineage.complete === false
                  ? " · 有缺失"
                  : " · 完整性未知"}
            </Badge>
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
          <Field label="启动时间">
            <span className="font-mono text-xs">
              {host.boot_time ? fmtTimestampFull(host.boot_time) : EM_DASH}
            </span>
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
          <Field label="来源 Agent">
            {report.source_agent_id ? (
              <CopyableId value={report.source_agent_id} />
            ) : (
              <span className="text-muted-foreground">{EM_DASH}</span>
            )}
          </Field>
          <Field label="来源目标">
            {report.source_target_id ? (
              <CopyableId value={report.source_target_id} />
            ) : (
              <span className="text-muted-foreground">{EM_DASH}</span>
            )}
          </Field>
        </CardContent>
      </Card>

      {assetTotal > 0 && (
        <section id="assets" className="flex scroll-mt-6 flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Database className="text-muted-foreground size-4" />
            <h2 className="text-sm font-semibold">资产清单</h2>
            <Badge variant="outline">共 {assetTotal} 项</Badge>
            {ASSET_KIND_ORDER.filter((kind) => (assetKindTotals[kind] ?? 0) > 0).map((kind) => (
              <Badge key={kind} variant="secondary">
                {KIND_META[kind].label} {assetKindTotals[kind] ?? 0}
              </Badge>
            ))}
          </div>
          <PageNav
            page={assetPage}
            count={visibleAssets.length}
            previousHref={
              assetPage > 0
                ? reportPageHref(report.report_id, assetPage - 1, findingPage, "assets")
                : undefined
            }
            nextHref={
              assetHasMore
                ? reportPageHref(report.report_id, assetPage + 1, findingPage, "assets")
                : undefined
            }
            ariaLabel="资产分页"
          />
        </section>
      )}

      {securityProducts.length > 0 && (
        <AssetSection
          kind="security_product"
          count={securityProducts.length}
          total={assetKindTotals.security_product}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>产品</TableHead>
              <TableHead>运行状态</TableHead>
              <TableHead className="hidden sm:table-cell">防护能力</TableHead>
              <TableHead className="hidden md:table-cell">版本</TableHead>
              <TableHead className="hidden lg:table-cell">安全情报 / 最近扫描</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {securityProducts.map((product) => (
              <TableRow key={product.asset_id}>
                <TableCell>
                  <span className="block text-sm font-medium">{product.name}</span>
                  <span className="text-muted-foreground text-xs">{product.vendor}</span>
                </TableCell>
                <TableCell>
                  <Badge variant={product.status === "unavailable" ? "destructive" : "outline"}>
                    {SECURITY_STATUS_LABEL[product.status]}
                  </Badge>
                  {product.mode && (
                    <span className="text-muted-foreground mt-1 block font-mono text-xs">
                      {product.mode}
                    </span>
                  )}
                </TableCell>
                <TableCell className="hidden text-xs sm:table-cell">
                  <span className="block">实时 {enabledLabel(product.real_time_protection)}</span>
                  <span className="block">行为 {enabledLabel(product.behavior_monitor)}</span>
                  <span className="block">IOAV {enabledLabel(product.ioav_protection)}</span>
                  <span className="block">篡改保护 {enabledLabel(product.tamper_protection)}</span>
                  <span className="block">云保护 {enabledLabel(product.cloud_protection)}</span>
                </TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">
                  <span className="block">产品 {orDash(product.product_version)}</span>
                  <span className="block">引擎 {orDash(product.engine_version)}</span>
                  <span className="block">情报 {orDash(product.signature_version)}</span>
                </TableCell>
                <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                  <span className="block">
                    情报更新 {fmtTimestampFull(product.signature_updated_at)}
                    {product.signatures_out_of_date === true ? " · 已过期" : ""}
                  </span>
                  <span className="block">
                    快速扫描 {fmtTimestampFull(product.last_quick_scan_at)}
                  </span>
                  <span className="block">
                    全盘扫描 {fmtTimestampFull(product.last_full_scan_at)}
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {/* packages */}
      {packages.length > 0 && (
        <AssetSection kind="package" count={packages.length} total={assetKindTotals.package}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>名称</TableHead>
              <TableHead>版本</TableHead>
              <TableHead className="hidden sm:table-cell">来源</TableHead>
              <TableHead className="hidden md:table-cell">生态</TableHead>
              <TableHead className="hidden lg:table-cell">安装路径 / 归属</TableHead>
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
                <TableCell className="text-muted-foreground hidden max-w-64 font-mono text-xs lg:table-cell">
                  <span className="block break-all">{orDash(pkg.install_path)}</span>
                  {pkg.parent_asset_id && (
                    <span className="mt-1 block break-all">归属 {pkg.parent_asset_id}</span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {containers.length > 0 && (
        <AssetSection
          kind="container"
          count={containers.length}
          total={assetKindTotals.container}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>名称</TableHead>
              <TableHead>运行时</TableHead>
              <TableHead className="hidden sm:table-cell">镜像</TableHead>
              <TableHead className="hidden md:table-cell">状态</TableHead>
              <TableHead className="hidden lg:table-cell">容器 ID / 路径</TableHead>
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
                <TableCell className="text-muted-foreground hidden max-w-72 font-mono text-xs lg:table-cell">
                  <span className="block break-all">ID {orDash(ctr.container_id)}</span>
                  <span className="block break-all">配置 {orDash(ctr.config_path)}</span>
                  <span className="block break-all">rootfs {orDash(ctr.rootfs_path)}</span>
                  {ctr.parent_asset_id && (
                    <span className="block break-all">归属 {ctr.parent_asset_id}</span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {images.length > 0 && (
        <AssetSection kind="image" count={images.length} total={assetKindTotals.image}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>名称</TableHead>
              <TableHead>运行时</TableHead>
              <TableHead className="hidden sm:table-cell">镜像 ID</TableHead>
              <TableHead className="hidden md:table-cell">标签</TableHead>
              <TableHead className="hidden lg:table-cell">创建时间 / 归属</TableHead>
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
                  <span className="break-all" title={img.image_id ?? undefined}>
                    {orDash(img.image_id)}
                  </span>
                </TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">
                  {img.tags && img.tags.length > 0 ? img.tags.join(", ") : EM_DASH}
                </TableCell>
                <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                  <span className="block">
                    {img.created ? fmtTimestampFull(img.created) : EM_DASH}
                  </span>
                  {img.parent_asset_id && (
                    <span className="block break-all">归属 {img.parent_asset_id}</span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {/* services */}
      {services.length > 0 && (
        <AssetSection kind="service" count={services.length} total={assetKindTotals.service}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>名称</TableHead>
              <TableHead>状态</TableHead>
              <TableHead className="hidden sm:table-cell">可执行路径</TableHead>
              <TableHead className="hidden lg:table-cell">归属</TableHead>
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
                <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                  {orDash(svc.parent_asset_id)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {/* ports */}
      {ports.length > 0 && (
        <AssetSection kind="port" count={ports.length} total={assetKindTotals.port}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>协议 / 端口</TableHead>
              <TableHead>监听地址</TableHead>
              <TableHead className="hidden sm:table-cell">进程</TableHead>
              <TableHead className="hidden md:table-cell">PID</TableHead>
              <TableHead className="hidden lg:table-cell">归属</TableHead>
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
                <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                  {orDash(port.parent_asset_id)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {/* accounts */}
      {accounts.length > 0 && (
        <AssetSection kind="account" count={accounts.length} total={assetKindTotals.account}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>用户名</TableHead>
              <TableHead>UID</TableHead>
              <TableHead className="hidden sm:table-cell">Shell</TableHead>
              <TableHead className="hidden md:table-cell">最近登录</TableHead>
              <TableHead className="hidden lg:table-cell">归属</TableHead>
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
                <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                  {orDash(acct.parent_asset_id)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {/* credentials */}
      {credentials.length > 0 && (
        <AssetSection
          kind="credential"
          count={credentials.length}
          total={assetKindTotals.credential}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>类型</TableHead>
              <TableHead>指纹</TableHead>
              <TableHead className="hidden sm:table-cell">所有者</TableHead>
              <TableHead className="hidden md:table-cell">路径</TableHead>
              <TableHead className="hidden lg:table-cell">归属</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {credentials.map((cred) => (
              <TableRow key={cred.asset_id}>
                <TableCell>
                  <Badge variant="outline">{cred.credential_kind}</Badge>
                </TableCell>
                <TableCell className="font-mono text-xs break-all">{cred.fingerprint}</TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  {orDash(cred.owner)}
                </TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">
                  {orDash(cred.path)}
                </TableCell>
                <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                  {orDash(cred.parent_asset_id)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {assetTotal === 0 && (
        <EmptyState
          icon={Database}
          title="未采集到资产"
          description="本次采集没有发现可上报的资产清单。"
        />
      )}

      {/* vulnerabilities */}
      <section id="findings" className="flex scroll-mt-6 flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Bug className="text-muted-foreground size-4" />
          <h2 className="text-sm font-semibold">检测发现</h2>
          <span className="text-muted-foreground text-xs tabular-nums">{vulnerabilityTotal}</span>
          {vulnerabilityTotal > 0 && (
            <Badge variant="outline">
              本页 {findingStart + 1}–{findingStart + vulns.length} / 共 {vulnerabilityTotal}
            </Badge>
          )}
          {detectionVerified ? (
            <Badge variant="secondary">
              已完整汇总本次启用检测 {detection.lineage.received_chunks}/
              {detection.lineage.expected_chunks ?? detection.lineage.received_chunks}
            </Badge>
          ) : detection.status === "found" ? (
            <Badge variant={detection.lineage.complete === false ? "destructive" : "outline"}>
              派生检测分片 {detection.lineage.received_chunks}/
              {detection.lineage.expected_chunks ?? "?"} · 未确认完整
            </Badge>
          ) : detection.status === "missing" ? (
            <Badge variant="outline">未生成派生检测记录</Badge>
          ) : (
            <Badge variant="outline">派生检测暂不可用</Badge>
          )}
        </div>
        {detection.status === "found" && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {detectionStatuses.map((status) => (
              <Badge
                key={status}
                variant={status === "complete" ? "secondary" : "outline"}
              >
                {DETECTION_STATUS_LABEL[status]}
              </Badge>
            ))}
            <Badge variant="outline">已纳入 OSV 匹配 {scannedPackages}</Badge>
            {unresolvedPackages > 0 && (
              <Badge variant="outline">
                生态无法解析、未纳入 OSV 匹配 {unresolvedPackages}
              </Badge>
            )}
            {uncoveredPackages > 0 && (
              <Badge variant="outline">
                OSV 未覆盖（未同步或不支持）{uncoveredPackages}
              </Badge>
            )}
            {coverageReasons.map((reason) => (
              <Badge key={reason} variant="outline">
                原因 {detectionReasonLabel(reason)}
              </Badge>
            ))}
            {truncationReasons.map((reason) => (
              <Badge key={reason} variant="destructive">
                发现已截断 · {detectionReasonLabel(reason)}
              </Badge>
            ))}
          </div>
        )}
        {detection.status === "found" && (
          <div className="flex flex-col gap-2">
            <h3 className="text-xs font-medium">检测器 / 生态覆盖矩阵</h3>
            <CoverageMatrix rows={coverageMatrix} />
          </div>
        )}
        {vulnerabilityTotal === 0 ? (
          <EmptyState
            icon={Bug}
            title={
              detectionVerified
                ? "本次已启用检测未返回发现"
                : "尚不能确认本次已启用检测无发现"
            }
            description={
              detectionVerified
                ? "资产上报与派生检测分片均已完整汇总，OSV 软件包匹配已完成，且本次任务实际启用的检测未返回发现；未启用的检测项目不在此结论范围内。"
                : detection.status === "found"
                  ? "已展示当前收到的记录，但资产上报或派生检测分片尚未确认完整，或 OSV 软件包匹配覆盖不完整；不能据此确认本次已启用检测无发现。"
                : detection.status === "missing"
                  ? "当前收到的资产报告没有内嵌发现，且 Analyzer 未保存该报告的派生检测记录；这不代表本次已启用检测无发现。"
                  : "当前收到的资产报告没有内嵌发现，但暂时无法读取 Analyzer 派生检测结果，无法确认本次已启用检测的结论。"
            }
          />
        ) : (
          <div className="flex flex-col gap-2">
            {vulns.map((v: Vulnerability) => (
              <Card
                key={`${v.source}:${v.vuln_id}:${v.affected_asset_id}:${v.parent_asset_id ?? ""}:${v.evidence ?? ""}`}
                size="sm"
                className="gap-2 p-4"
              >
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                  <SeverityBadge severity={v.severity} />
                  <span className="font-mono text-sm font-medium">{v.vuln_id}</span>
                  <span className="text-muted-foreground text-xs">来源 {v.source}</span>
                  {v.cvss_score != null && (
                    <Badge variant="outline" className="tabular-nums">
                      CVSS {v.cvss_score}
                    </Badge>
                  )}
                  {v.parent_asset_id && (
                    <Badge variant="outline" className="text-xs">
                      {v.parent_asset_id.startsWith("ctr-") ? "容器" : "镜像"} {v.parent_asset_id}
                    </Badge>
                  )}
                  <span className="text-muted-foreground ml-auto font-mono text-xs">
                    {v.affected_asset_id}
                  </span>
                </div>
                {v.evidence && <p className="text-muted-foreground text-xs">{v.evidence}</p>}
                {v.references && v.references.length > 0 && (
                  <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
                    <span className="text-muted-foreground">参考</span>
                    {v.references.map((reference) =>
                      /^https?:\/\//i.test(reference) ? (
                        <a
                          key={reference}
                          href={reference}
                          target="_blank"
                          rel="noreferrer"
                          className="max-w-full break-all text-primary hover:underline"
                        >
                          {reference}
                        </a>
                      ) : (
                        <span key={reference} className="break-all font-mono">
                          {reference}
                        </span>
                      ),
                    )}
                  </div>
                )}
              </Card>
            ))}
          </div>
        )}
        {vulnerabilityTotal > 0 && (
          <PageNav
            page={findingPage}
            count={vulns.length}
            previousHref={
              findingPage > 0
                ? reportPageHref(report.report_id, assetPage, findingPage - 1, "findings")
                : undefined
            }
            nextHref={
              findingHasMore
                ? reportPageHref(report.report_id, assetPage, findingPage + 1, "findings")
                : undefined
            }
            ariaLabel="发现分页"
          />
        )}
      </section>
    </div>
  );
}

export default async function ReportPage({
  params,
  searchParams,
}: {
  params: Promise<{ reportId: string }>;
  searchParams: Promise<{
    assets_page?: string | string[];
    findings_page?: string | string[];
  }>;
}) {
  const [{ reportId }, query] = await Promise.all([params, searchParams]);
  const requestedAssetPage = Math.min(parsePage(query.assets_page), MAX_DETAIL_PAGE);
  const requestedFindingPage = Math.min(parsePage(query.findings_page), MAX_DETAIL_PAGE);

  let detail: ReportDetailPage;
  try {
    detail = await getReportDetailPage(
      reportId,
      requestedAssetPage,
      requestedFindingPage,
      ASSET_PAGE_SIZE,
      FINDING_PAGE_SIZE,
    );
  } catch (err) {
    if (err instanceof FormApiError && err.status === 404) notFound();
    throw err;
  }
  const report: AssetReport = {
    ...detail.report,
    assets: detail.assets,
    vulnerabilities: [],
  };
  const detection: DetectionState = {
    status: "found",
    lineage: {
      ...detail.detection_lineage,
      records: detail.detection_records.map((record) => ({
        ...record,
        vulnerabilities: [],
      })),
    },
  };

  return (
    <div className="mx-auto w-full max-w-5xl flex-1 p-6 sm:p-8">
      <nav className="text-muted-foreground mb-6 flex items-center gap-1 text-sm">
        <Link href="/reports" className="hover:text-foreground">
          资产报告
        </Link>
        <ChevronRight className="size-4" />
        <span className="text-foreground font-mono">{report.host.hostname}</span>
      </nav>
      <ReportDetail
        report={report}
        assetLineage={detail.asset_lineage}
        detection={detection}
        assetTotal={detail.asset_total}
        assetKindTotals={detail.asset_kind_totals}
        assetPage={detail.asset_page}
        assetHasMore={detail.asset_has_more}
        vulnerabilities={detail.vulnerabilities}
        vulnerabilityTotal={detail.vulnerability_total}
        findingPage={detail.finding_page}
        findingPageSize={detail.finding_page_size}
        findingHasMore={detail.finding_has_more}
      />
    </div>
  );
}
