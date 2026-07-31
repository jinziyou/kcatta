import {
  Box,
  Bug,
  ChevronRight,
  Cpu,
  Database,
  FileLock2,
  HardDrive,
  Key,
  Layers,
  Network,
  Package as PackageIcon,
  Plug,
  Server,
  ShieldCheck,
  TimerReset,
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
  CollectionKind,
  CollectionRun,
  DataService,
  AssetReport,
  Credential,
  DetectionResult,
  FilesystemMount,
  Image,
  NetworkService,
  Package,
  PersistenceEntry,
  Port,
  ProcessAsset,
  SecurityControl,
  SensitiveFile,
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
  process: { label: "进程", icon: Cpu },
  network_service: { label: "网络服务", icon: Network },
  filesystem_mount: { label: "文件系统", icon: HardDrive },
  data_service: { label: "数据库 / 队列", icon: Database },
  security_control: { label: "安全控制", icon: ShieldCheck },
  sensitive_file: { label: "敏感配置", icon: FileLock2 },
  persistence_entry: { label: "持久化项", icon: TimerReset },
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
  "security_control",
  "data_service",
  "network_service",
  "persistence_entry",
  "sensitive_file",
  "service",
  "port",
  "process",
  "filesystem_mount",
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

const CONTROL_STATUS_LABEL: Record<SecurityControl["status"], string> = {
  active: "运行中",
  inactive: "未运行",
  configured: "已配置，运行态未验证",
  unavailable: "未发现",
  unknown: "未知",
};

const COLLECTION_KIND_LABEL: Record<CollectionKind, string> = {
  host: "主机身份",
  package: "软件包",
  service: "服务",
  port: "监听端口",
  process: "进程",
  network_service: "网络服务归属",
  filesystem_mount: "文件系统",
  database: "数据库",
  message_queue: "消息队列",
  cache: "缓存",
  security_control: "安全控制",
  sensitive_file: "敏感配置",
  persistence_entry: "持久化项",
  account: "账号",
  credential: "凭据指纹",
  container: "容器",
  image: "镜像",
};

const COLLECTION_STATUS_LABEL: Record<CollectionRun["status"], string> = {
  complete: "完成",
  partial: "部分完成",
  failed: "失败",
  disabled: "已禁用",
};

const CONTROL_TYPE_LABEL: Record<SecurityControl["control"], string> = {
  firewall: "主机防火墙",
  mandatory_access_control: "强制访问控制",
  audit: "主机审计",
  time_sync: "时间同步",
  log_forwarding: "日志转发",
};

const DATA_SERVICE_CATEGORY_LABEL: Record<DataService["category"], string> = {
  database: "数据库",
  message_queue: "消息队列",
  cache: "缓存",
};

const DATA_METADATA_STATUS_LABEL: Record<
  NonNullable<NonNullable<DataService["principal_coverage"]>["status"]>,
  string
> = {
  complete: "完成",
  partial: "部分完成",
  not_authorized: "未授权",
  unavailable: "不可用",
  unsupported: "不支持",
};

const SENSITIVE_FILE_CATEGORY_LABEL: Record<SensitiveFile["category"], string> = {
  identity: "身份",
  ssh: "SSH",
  privilege: "提权策略",
  service: "服务",
  scheduler: "计划任务",
  database: "数据库 / 队列",
  application: "应用",
};

const PERSISTENCE_TYPE_LABEL: Record<PersistenceEntry["entry_type"], string> = {
  systemd_service: "systemd 服务",
  systemd_timer: "systemd 定时器",
  cron: "Cron",
  at_job: "at 任务",
  shell_profile: "Shell 启动文件",
  kernel_module: "内核模块",
  authorized_key: "SSH 授权密钥",
  container_restart: "容器重启策略",
};

function formatBytes(value: number | null | undefined) {
  if (value === null || value === undefined) return EM_DASH;
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function formatMode(value: number | null | undefined) {
  return value == null ? EM_DASH : value.toString(8).padStart(4, "0");
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
  const processes: ProcessAsset[] = [];
  const networkServices: NetworkService[] = [];
  const filesystemMounts: FilesystemMount[] = [];
  const dataServices: DataService[] = [];
  const securityControls: SecurityControl[] = [];
  const sensitiveFiles: SensitiveFile[] = [];
  const persistenceEntries: PersistenceEntry[] = [];
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
      case "process":
        processes.push(asset);
        break;
      case "network_service":
        networkServices.push(asset);
        break;
      case "filesystem_mount":
        filesystemMounts.push(asset);
        break;
      case "data_service":
        dataServices.push(asset);
        break;
      case "security_control":
        securityControls.push(asset);
        break;
      case "sensitive_file":
        sensitiveFiles.push(asset);
        break;
      case "persistence_entry":
        persistenceEntries.push(asset);
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

      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldCheck className="text-muted-foreground size-4" />
          <h2 className="text-sm font-semibold">采集覆盖矩阵</h2>
          {report.collection_runs == null ? (
            <Badge variant="destructive">旧版报告 · 覆盖未知</Badge>
          ) : (
            <Badge
              variant={
                report.collection_runs.every((run) =>
                  ["complete", "disabled"].includes(run.status),
                )
                  ? "secondary"
                  : "destructive"
              }
            >
              {report.collection_runs.length} 类均有显式状态
            </Badge>
          )}
        </div>
        {report.collection_runs == null ? (
          <EmptyState
            icon={ShieldCheck}
            title="本次报告没有采集覆盖声明"
            description="无法区分零发现、未启用和采集失败；请使用新版 Agent 复扫。"
          />
        ) : (
          <div className="overflow-hidden rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/40 hover:bg-muted/40">
                  <TableHead>采集类别</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead className="text-right">记录数</TableHead>
                  <TableHead className="hidden md:table-cell">说明</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {report.collection_runs.map((run) => (
                  <TableRow key={run.collector}>
                    <TableCell className="font-medium">
                      {COLLECTION_KIND_LABEL[run.collector]}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          run.status === "complete"
                            ? "secondary"
                            : run.status === "partial" || run.status === "failed"
                              ? "destructive"
                              : "outline"
                        }
                      >
                        {COLLECTION_STATUS_LABEL[run.status]}
                        {run.status === "complete" && run.record_count === 0
                          ? " · 零发现"
                          : ""}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">
                      {run.record_count}
                    </TableCell>
                    <TableCell className="text-muted-foreground hidden font-mono text-xs md:table-cell">
                      {orDash(run.reason)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

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

      {securityControls.length > 0 && (
        <AssetSection
          kind="security_control"
          count={securityControls.length}
          total={assetKindTotals.security_control}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>控制项</TableHead>
              <TableHead>状态</TableHead>
              <TableHead className="hidden sm:table-cell">实现 / 模式</TableHead>
              <TableHead className="hidden lg:table-cell">证据摘要</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {securityControls.map((control) => (
              <TableRow key={control.asset_id}>
                <TableCell className="text-xs font-medium">
                  {CONTROL_TYPE_LABEL[control.control]}
                </TableCell>
                <TableCell>
                  <Badge
                    variant={
                      control.status === "active"
                        ? "secondary"
                        : control.status === "inactive" || control.status === "unavailable"
                          ? "destructive"
                          : "outline"
                    }
                  >
                    {CONTROL_STATUS_LABEL[control.status]}
                  </Badge>
                </TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  <span className="block">{control.name}</span>
                  {control.mode && (
                    <span className="text-muted-foreground block">{control.mode}</span>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground hidden text-xs lg:table-cell">
                  {orDash(control.details)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {dataServices.length > 0 && (
        <AssetSection
          kind="data_service"
          count={dataServices.length}
          total={assetKindTotals.data_service}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>类型 / 引擎</TableHead>
              <TableHead>端点</TableHead>
              <TableHead className="hidden sm:table-cell">安全状态</TableHead>
              <TableHead className="hidden md:table-cell">配置 / 数据目录</TableHead>
              <TableHead className="hidden lg:table-cell">发现依据</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {dataServices.map((service) => (
              <TableRow key={service.asset_id}>
                <TableCell>
                  <span className="block text-sm font-medium">{service.engine}</span>
                  <span className="text-muted-foreground text-xs">
                    {DATA_SERVICE_CATEGORY_LABEL[service.category]} · {service.version ?? "版本未知"}
                  </span>
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {service.endpoints && service.endpoints.length > 0
                    ? service.endpoints.join(", ")
                    : "未发现运行端点"}
                </TableCell>
                <TableCell className="hidden text-xs sm:table-cell">
                  <span className="block">TLS {enabledLabel(service.tls_enabled)}</span>
                  <span className="block">
                    认证 {enabledLabel(service.authentication_enabled)}
                  </span>
                  <span className="block">匿名 {enabledLabel(service.anonymous_access)}</span>
                  <span className="block">审计 {enabledLabel(service.audit_enabled)}</span>
                  <span className="block">复制 {enabledLabel(service.replication_enabled)}</span>
                  <span className="block">备份 {enabledLabel(service.backup_enabled)}</span>
                </TableCell>
                <TableCell className="text-muted-foreground hidden max-w-96 font-mono text-xs md:table-cell">
                  <span className="block break-all">
                    配置{" "}
                    {service.config_paths && service.config_paths.length > 0
                      ? service.config_paths.join(", ")
                      : EM_DASH}
                  </span>
                  <span className="block break-all">
                    数据{" "}
                    {service.data_paths && service.data_paths.length > 0
                      ? service.data_paths.join(", ")
                      : EM_DASH}
                  </span>
                </TableCell>
                <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                  <span className="block">{service.discovery_source}</span>
                  <span className="block break-all">
                    {orDash(service.process_asset_id)}
                  </span>
                  <span className="mt-1 block">
                    角色{" "}
                    {
                      DATA_METADATA_STATUS_LABEL[
                        service.principal_coverage?.status ?? "unsupported"
                      ]
                    }{" "}
                    · {service.principal_coverage?.record_count ?? 0}
                  </span>
                  {(service.principals?.length ?? 0) > 0 && (
                    <span className="block break-all">
                      {service.principals?.map((principal) => principal.name).join(", ")}
                    </span>
                  )}
                  <span className="mt-1 block">
                    对象{" "}
                    {
                      DATA_METADATA_STATUS_LABEL[
                        service.object_coverage?.status ?? "unsupported"
                      ]
                    }{" "}
                    · {service.object_coverage?.record_count ?? 0}
                  </span>
                  {(service.objects?.length ?? 0) > 0 && (
                    <span className="block break-all">
                      {service.objects
                        ?.map((object) => `${object.object_type}:${object.name}`)
                        .join(", ")}
                    </span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {persistenceEntries.length > 0 && (
        <AssetSection
          kind="persistence_entry"
          count={persistenceEntries.length}
          total={assetKindTotals.persistence_entry}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>机制 / 名称</TableHead>
              <TableHead>来源</TableHead>
              <TableHead className="hidden sm:table-cell">身份 / 状态</TableHead>
              <TableHead className="hidden md:table-cell">命令摘要</TableHead>
              <TableHead className="hidden lg:table-cell">风险 / 摘要</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {persistenceEntries.map((entry) => (
              <TableRow key={entry.asset_id}>
                <TableCell>
                  <span className="block text-sm font-medium">{entry.name}</span>
                  <span className="text-muted-foreground text-xs">
                    {PERSISTENCE_TYPE_LABEL[entry.entry_type]}
                  </span>
                </TableCell>
                <TableCell className="max-w-80 font-mono text-xs">
                  <span className="block break-all">{entry.source_path}</span>
                  <span className="text-muted-foreground block">
                    修改于 {entry.modified_at ? fmtTimestampFull(entry.modified_at) : EM_DASH}
                  </span>
                </TableCell>
                <TableCell className="hidden text-xs sm:table-cell">
                  <span className="block font-mono">{entry.principal ?? EM_DASH}</span>
                  <Badge variant={entry.enabled === false ? "destructive" : "outline"}>
                    {entry.enabled == null ? "状态未知" : entry.enabled ? "已启用" : "未启用"}
                  </Badge>
                </TableCell>
                <TableCell className="hidden max-w-96 font-mono text-xs md:table-cell">
                  <span className="block break-all">{entry.command ?? EM_DASH}</span>
                  {entry.command_redacted && (
                    <Badge variant="outline" className="mt-1">
                      参数已脱敏
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground hidden max-w-80 font-mono text-xs lg:table-cell">
                  {entry.risk_flags && entry.risk_flags.length > 0 ? (
                    <Badge variant="destructive">{entry.risk_flags.join(", ")}</Badge>
                  ) : (
                    <span className="block">未发现权限风险</span>
                  )}
                  <span
                    className="mt-1 block truncate"
                    title={entry.content_sha256 ?? undefined}
                  >
                    SHA-256 {entry.content_sha256 ?? EM_DASH}
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {sensitiveFiles.length > 0 && (
        <AssetSection
          kind="sensitive_file"
          count={sensitiveFiles.length}
          total={assetKindTotals.sensitive_file}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>分类 / 路径</TableHead>
              <TableHead>属主 / 权限</TableHead>
              <TableHead className="hidden sm:table-cell">大小 / 修改时间</TableHead>
              <TableHead className="hidden md:table-cell">风险属性</TableHead>
              <TableHead className="hidden lg:table-cell">内容摘要</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sensitiveFiles.map((file) => {
              const risky =
                file.world_writable ||
                file.group_writable ||
                file.setuid ||
                file.setgid ||
                file.acl_risk === true;
              return (
                <TableRow key={file.asset_id}>
                  <TableCell className="max-w-96">
                    <span className="block text-xs font-medium">
                      {SENSITIVE_FILE_CATEGORY_LABEL[file.category]}
                    </span>
                    <span className="block break-all font-mono text-xs">{file.path}</span>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    <span className="block">
                      {file.owner_uid ?? EM_DASH}:{file.owner_gid ?? EM_DASH}
                    </span>
                    <span className="text-muted-foreground block">
                      mode {formatMode(file.mode)}
                    </span>
                  </TableCell>
                  <TableCell className="hidden text-xs sm:table-cell">
                    <span className="block">{formatBytes(file.size_bytes)}</span>
                    <span className="text-muted-foreground block font-mono">
                      {file.modified_at ? fmtTimestampFull(file.modified_at) : EM_DASH}
                    </span>
                  </TableCell>
                  <TableCell className="hidden text-xs md:table-cell">
                    <Badge variant={risky ? "destructive" : "secondary"}>
                      {risky ? "存在权限风险" : "未发现危险权限"}
                    </Badge>
                    <span className="text-muted-foreground mt-1 block">
                      全局写 {file.world_writable ? "是" : "否"} · 组写{" "}
                      {file.group_writable ? "是" : "否"} · SUID {file.setuid ? "是" : "否"} ·
                      SGID {file.setgid ? "是" : "否"} · ACL{" "}
                      {file.acl_risk == null ? "未验证" : file.acl_risk ? "风险" : "正常"}
                    </span>
                  </TableCell>
                  <TableCell className="text-muted-foreground hidden max-w-80 font-mono text-xs lg:table-cell">
                    <span className="block truncate" title={file.sha256 ?? undefined}>
                      SHA-256 {file.sha256 ?? EM_DASH}
                    </span>
                    <span className="block">只保存摘要，不上传正文</span>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </AssetSection>
      )}

      {networkServices.length > 0 && (
        <AssetSection
          kind="network_service"
          count={networkServices.length}
          total={assetKindTotals.network_service}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>协议 / 端口</TableHead>
              <TableHead>监听地址</TableHead>
              <TableHead className="hidden sm:table-cell">进程身份</TableHead>
              <TableHead className="hidden md:table-cell">可执行文件</TableHead>
              <TableHead className="hidden lg:table-cell">服务 / 容器 / 包</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {networkServices.map((service) => (
              <TableRow key={service.asset_id}>
                <TableCell className="font-mono text-xs font-medium">
                  {service.proto}/{service.port}
                </TableCell>
                <TableCell className="font-mono text-xs">{service.listen_addr}</TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">
                  {service.process_asset_id ? (
                    <>
                      <span className="block">
                        {service.process_name ?? EM_DASH} · PID{" "}
                        {service.process_asset_id.replace("process-", "")}
                      </span>
                      <span className="text-muted-foreground block">
                        {service.username ?? service.uid ?? EM_DASH}
                      </span>
                    </>
                  ) : (
                    <Badge variant="destructive">进程归属未解析</Badge>
                  )}
                </TableCell>
                <TableCell className="hidden max-w-80 font-mono text-xs md:table-cell">
                  <span className="block break-all">{orDash(service.exe_path)}</span>
                  {service.executable_sha256 && (
                    <span
                      className="text-muted-foreground block truncate"
                      title={service.executable_sha256}
                    >
                      SHA-256 {service.executable_sha256}
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                  <span className="block">单元 {orDash(service.systemd_unit)}</span>
                  <span className="block">容器 {orDash(service.container_id)}</span>
                  <span className="block">软件包 {orDash(service.package_name)}</span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {filesystemMounts.length > 0 && (
        <AssetSection
          kind="filesystem_mount"
          count={filesystemMounts.length}
          total={assetKindTotals.filesystem_mount}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>挂载点</TableHead>
              <TableHead>来源 / 类型</TableHead>
              <TableHead className="hidden sm:table-cell">容量</TableHead>
              <TableHead className="hidden md:table-cell">安全属性</TableHead>
              <TableHead className="hidden lg:table-cell">挂载参数</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filesystemMounts.map((mount) => (
              <TableRow key={mount.asset_id}>
                <TableCell className="font-mono text-xs font-medium">
                  {mount.mount_point}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  <span className="block break-all">{mount.source}</span>
                  <span className="text-muted-foreground block">{mount.fs_type}</span>
                </TableCell>
                <TableCell className="hidden text-xs sm:table-cell">
                  <span className="block">总量 {formatBytes(mount.total_bytes)}</span>
                  <span className="block">可用 {formatBytes(mount.available_bytes)}</span>
                  <span className="block">
                    inode{" "}
                    {mount.available_inodes == null
                      ? EM_DASH
                      : `${mount.available_inodes}/${mount.total_inodes ?? "?"}`}
                  </span>
                </TableCell>
                <TableCell className="hidden text-xs md:table-cell">
                  <Badge variant={mount.readonly ? "secondary" : "outline"}>
                    {mount.readonly ? "只读" : "可写"}
                  </Badge>
                  {mount.remote && (
                    <Badge variant="outline" className="ml-1">
                      远程
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground hidden max-w-96 font-mono text-xs lg:table-cell">
                  {mount.options?.join(", ") || EM_DASH}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
      )}

      {processes.length > 0 && (
        <AssetSection kind="process" count={processes.length} total={assetKindTotals.process}>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead>PID / 进程</TableHead>
              <TableHead>运行身份</TableHead>
              <TableHead className="hidden sm:table-cell">可执行文件</TableHead>
              <TableHead className="hidden md:table-cell">命令行</TableHead>
              <TableHead className="hidden lg:table-cell">单元 / 容器</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {processes.map((process) => (
              <TableRow key={process.asset_id}>
                <TableCell className="font-mono text-xs">
                  <span className="block font-medium">
                    {process.pid} · {process.name}
                  </span>
                  <span className="text-muted-foreground block">
                    PPID {process.ppid ?? EM_DASH}
                  </span>
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {process.username ?? process.uid ?? EM_DASH}
                </TableCell>
                <TableCell className="hidden max-w-80 font-mono text-xs sm:table-cell">
                  <span className="block break-all">{orDash(process.exe_path)}</span>
                  {process.executable_sha256 && (
                    <span
                      className="text-muted-foreground block truncate"
                      title={process.executable_sha256}
                    >
                      SHA-256 {process.executable_sha256}
                    </span>
                  )}
                </TableCell>
                <TableCell className="hidden max-w-96 font-mono text-xs md:table-cell">
                  <span className="block break-all">{orDash(process.command_line)}</span>
                  {process.command_line_redacted && (
                    <Badge variant="outline" className="mt-1">
                      已脱敏
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                  <span className="block">单元 {orDash(process.systemd_unit)}</span>
                  <span className="block">容器 {orDash(process.container_id)}</span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </AssetSection>
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
