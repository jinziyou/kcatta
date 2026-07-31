/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

/**
 * Stable identifier assigned by the scanner
 */
export type AssetId = string;
/**
 * OSV ecosystem for vulnerability matching, e.g. 'Debian:12', 'PyPI', 'npm'. When unset, detection falls back to the host's ecosystem derived from host.os.
 */
export type Ecosystem = string | null;
export type InstallPath = string | null;
export type Kind = "package";
export type Name = string;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId = string | null;
/**
 * Package manager, e.g. apt / yum / pip / npm
 */
export type Source = string | null;
/**
 * Source package name when the package manager exposes it
 */
export type SourceName = string | null;
/**
 * Source package version used to build the installed binary package
 */
export type SourceVersion = string | null;
export type Version = string;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId1 = string;
export type ExecPath = string | null;
export type Kind1 = "service";
export type Name1 = string;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId1 = string | null;
/**
 * running / stopped / failed / ...
 */
export type Status = string;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId2 = string;
export type Kind2 = "port";
export type ListenAddr = string;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId2 = string | null;
export type Pid = number | null;
export type Port1 = number;
export type ProcessName = string | null;
export type Proto = "tcp" | "udp";
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId3 = string;
/**
 * Redacted command line; never contains raw credential arguments
 */
export type CommandLine = string | null;
/**
 * True when one or more command-line values were replaced
 */
export type CommandLineRedacted = boolean;
export type ContainerId = string | null;
export type ExePath = string | null;
export type ExecutableSha256 = string | null;
export type Kind3 = "process";
export type Name2 = string;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId3 = string | null;
export type Pid1 = number;
export type Ppid = number | null;
export type StartedAt = string | null;
export type SystemdUnit = string | null;
export type Uid = number | null;
export type Username = string | null;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId4 = string;
export type ContainerId1 = string | null;
export type ExePath1 = string | null;
export type ExecutableSha2561 = string | null;
export type Kind4 = "network_service";
export type ListenAddr1 = string;
export type PackageName = string | null;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId4 = string | null;
export type Port2 = number;
export type PortAssetId = string;
export type ProcessAssetId = string | null;
export type ProcessName1 = string | null;
export type Proto1 = "tcp" | "udp";
export type ServiceAssetId = string | null;
export type SystemdUnit1 = string | null;
export type Uid1 = number | null;
export type Username1 = string | null;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId5 = string;
export type AvailableBytes = number | null;
export type AvailableInodes = number | null;
export type FsType = string;
export type Kind5 = "filesystem_mount";
export type MountPoint = string;
/**
 * @maxItems 256
 */
export type Options = string[];
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId5 = string | null;
export type Readonly = boolean;
export type Remote = boolean;
export type Source1 = string;
export type TotalBytes = number | null;
export type TotalInodes = number | null;
export type AnonymousAccess = boolean | null;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId6 = string;
export type AuditEnabled = boolean | null;
export type AuthenticationEnabled = boolean | null;
export type BackupEnabled = boolean | null;
/**
 * Security-relevant stateful service family.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "DataServiceCategory".
 */
export type DataServiceCategory = "database" | "message_queue" | "cache";
/**
 * @maxItems 256
 */
export type ConfigPaths = string[];
/**
 * @maxItems 256
 */
export type DataPaths = string[];
/**
 * Non-secret evidence source, e.g. process, package, config, or listener
 */
export type DiscoverySource = string;
/**
 * @maxItems 256
 */
export type Endpoints = string[];
export type Engine = string;
export type Kind6 = "data_service";
/**
 * @maxItems 256
 */
export type NetworkServiceIds = string[];
export type Reason = string | null;
export type RecordCount = number;
/**
 * Outcome of a metadata-only runtime catalog query.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "DataMetadataStatus".
 */
export type DataMetadataStatus = "complete" | "partial" | "not_authorized" | "unavailable" | "unsupported";
export type AccessEnabled = boolean | null;
export type AclEntryCount = number | null;
export type BacklogMessages = number | null;
export type ConnectionLimit = number | null;
export type Name3 = string;
export type ObjectType = string;
export type Owner = string | null;
export type RetentionSeconds = number | null;
/**
 * @maxItems 256
 */
export type Objects = DataObject[];
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId6 = string | null;
export type CanLogin = boolean | null;
/**
 * @maxItems 256
 */
export type MemberOf = string[];
export type Name4 = string;
export type Privileged = boolean | null;
export type Replication = boolean | null;
/**
 * @maxItems 256
 */
export type Principals = DataPrincipal[];
export type ProcessAssetId1 = string | null;
export type ReplicationEnabled = boolean | null;
export type TlsEnabled = boolean | null;
export type Version1 = string | null;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId7 = string;
/**
 * Host control whose state affects collection trust or exposure.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "SecurityControlType".
 */
export type SecurityControlType = "firewall" | "mandatory_access_control" | "audit" | "time_sync" | "log_forwarding";
/**
 * Bounded non-secret summary; raw configuration is never embedded
 */
export type Details = string | null;
export type Kind7 = "security_control";
export type Mode = string | null;
export type Name5 = string;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId7 = string | null;
/**
 * Observed state without upgrading unknown/config-only evidence to active.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "SecurityControlStatus".
 */
export type SecurityControlStatus = "active" | "inactive" | "configured" | "unavailable" | "unknown";
/**
 * True only when an unsafe ACL is proven; None means ACL state was unavailable
 */
export type AclRisk = boolean | null;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId8 = string;
/**
 * Security purpose of a configuration or identity file.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "SensitiveFileCategory".
 */
export type SensitiveFileCategory =
  | "identity"
  | "ssh"
  | "privilege"
  | "service"
  | "scheduler"
  | "database"
  | "application";
export type GroupWritable = boolean;
export type Kind8 = "sensitive_file";
export type Mode1 = number | null;
export type ModifiedAt = string | null;
export type OwnerGid = number | null;
export type OwnerUid = number | null;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId8 = string | null;
export type Path = string;
export type Setgid = boolean;
export type Setuid = boolean;
/**
 * Digest of bounded regular-file bytes; raw contents are never transmitted
 */
export type Sha256 = string | null;
export type SizeBytes = number | null;
export type WorldWritable = boolean;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId9 = string;
/**
 * Redacted command summary; never raw credentials or configuration values
 */
export type Command = string | null;
export type CommandRedacted = boolean;
export type ContentSha256 = string | null;
export type Enabled = boolean | null;
/**
 * Mechanism capable of starting code automatically or granting access.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "PersistenceType".
 */
export type PersistenceType =
  | "systemd_service"
  | "systemd_timer"
  | "cron"
  | "at_job"
  | "shell_profile"
  | "kernel_module"
  | "authorized_key"
  | "container_restart";
export type Kind9 = "persistence_entry";
export type ModifiedAt1 = string | null;
export type Name6 = string;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId9 = string | null;
export type Principal = string | null;
/**
 * @maxItems 256
 */
export type RiskFlags = string[];
export type SourcePath = string;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId10 = string;
export type Kind10 = "account";
export type LastLogin = string | null;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId10 = string | null;
export type Shell = string | null;
export type Uid2 = number | null;
export type Username2 = string;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId11 = string;
/**
 * Kind of credential material discovered on a host.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "CredentialKind".
 */
export type CredentialKind = "ssh_key" | "api_key" | "password" | "token";
/**
 * Public fingerprint or hash; the secret itself MUST NEVER be transmitted
 */
export type Fingerprint = string;
export type Kind11 = "credential";
export type Owner1 = string | null;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId11 = string | null;
export type Path1 = string | null;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId12 = string;
/**
 * Path to the static metadata file under scan_root
 */
export type ConfigPath = string | null;
/**
 * Runtime container id when available
 */
export type ContainerId2 = string | null;
/**
 * Image reference when known from static metadata
 */
export type Image = string | null;
export type Kind12 = "container";
export type Name7 = string;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId12 = string | null;
/**
 * Merged container rootfs path under scan_root when resolved statically
 */
export type RootfsPath = string | null;
/**
 * Container runtime, e.g. docker / podman / containerd / kubernetes
 */
export type Runtime = string;
/**
 * Last known state, e.g. running / exited / created
 */
export type Status1 = string | null;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId13 = string;
/**
 * Image creation time from the image config, when available
 */
export type Created = string | null;
/**
 * Content-addressable image id (e.g. sha256:...)
 */
export type ImageId = string | null;
export type Kind13 = "image";
/**
 * Primary image reference (e.g. nginx:1.25), or short image id when untagged
 */
export type Name8 = string;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId13 = string | null;
/**
 * Image store / runtime, e.g. docker / podman
 */
export type Runtime1 = string;
/**
 * All repository tags / names for this image
 *
 * @maxItems 256
 */
export type Tags = string[];
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId14 = string;
export type BehaviorMonitor = boolean | null;
export type CloudProtection = boolean | null;
export type EngineVersion = string | null;
export type IoavProtection = boolean | null;
export type Kind14 = "security_product";
export type LastFullScanAt = string | null;
export type LastQuickScanAt = string | null;
/**
 * Vendor-specific running mode, for example Normal or Passive Mode
 */
export type Mode2 = string | null;
export type Name9 = string;
/**
 * Parent asset_id when this row came from a nested (container rootfs) scan
 */
export type ParentAssetId14 = string | null;
export type ProductVersion = string | null;
export type RealTimeProtection = boolean | null;
export type SignatureUpdatedAt = string | null;
export type SignatureVersion = string | null;
export type SignaturesOutOfDate = boolean | null;
export type Status2 = "active" | "passive" | "disabled" | "unavailable";
export type TamperProtection = boolean | null;
export type Vendor = string;
/**
 * @maxItems 4096
 */
export type Assets = (
  | Package
  | Service
  | Port
  | ProcessAsset
  | NetworkService
  | FilesystemMount
  | DataService
  | SecurityControl
  | SensitiveFile
  | PersistenceEntry
  | Account
  | Credential
  | Container
  | Image1
  | SecurityProduct
)[];
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CollectedAt = string;
/**
 * Inventory categories explicitly attempted by the producer. null means legacy/unknown; complete with record_count=0 is an audited zero result.
 */
export type CollectionRuns = CollectionRun[] | null;
/**
 * Inventory categories whose execution state must be explicit.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "CollectionKind".
 */
export type CollectionKind =
  | "host"
  | "package"
  | "service"
  | "port"
  | "process"
  | "network_service"
  | "filesystem_mount"
  | "database"
  | "message_queue"
  | "cache"
  | "security_control"
  | "sensitive_file"
  | "persistence_entry"
  | "account"
  | "credential"
  | "container"
  | "image";
export type Reason1 = string | null;
export type RecordCount1 = number;
/**
 * Producer-observed outcome for one inventory category.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "CollectionRunStatus".
 */
export type CollectionRunStatus = "complete" | "partial" | "failed" | "disabled";
/**
 * Detectors explicitly executed by the producer. null means legacy/unknown; an empty list means the producer confirms none were enabled.
 */
export type DetectorRuns = DetectorRun[] | null;
/**
 * Detection engines whose execution/coverage is surfaced to operators.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "DetectorKind".
 */
export type DetectorKind = "osv" | "debian_tracker" | "defender" | "malware" | "posture" | "secret";
export type FindingCount = number;
export type Reason2 = string | null;
/**
 * Producer-observed outcome for one enabled detector.
 */
export type DetectorRunStatus = "complete" | "partial" | "failed";
export type Arch = string | null;
export type BootTime = string | null;
export type HostId = string;
export type Hostname = string;
/**
 * @maxItems 256
 */
export type IpAddrs = string[];
export type Kernel = string | null;
/**
 * @maxItems 256
 */
export type MacAddrs = string[];
/**
 * OS family + version, e.g. 'Ubuntu 22.04'
 */
export type Os = string;
export type ReportId = string;
export type ScannerVersion = string;
/**
 * Authenticated Agent identity injected by Form; never trusted from payload
 */
export type SourceAgentId = string | null;
/**
 * Form-owned registered target attribution; absent only for unbound legacy telemetry
 */
export type SourceTargetId = string | null;
/**
 * References Asset.asset_id from the same report
 */
export type AffectedAssetId = string;
export type CvssScore = number | null;
/**
 * Short, human-readable proof (e.g. matched package version)
 */
export type Evidence = string | null;
/**
 * Owning image/container asset_id when the affected package came from a nested image/container scan; lets CVEs be grouped per image/container. None for host-level findings.
 */
export type ParentAssetId15 = string | null;
/**
 * @maxItems 256
 */
export type References = string[];
/**
 * Severity level of a finding, ordered from informational to critical.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Severity".
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";
/**
 * Scanner / engine that produced the finding
 */
export type Source2 = string;
/**
 * CVE id, vendor advisory id, or scanner-local id (e.g. GHSA-..., CVE-2024-1234)
 */
export type VulnId = string;
/**
 * @maxItems 4096
 */
export type Vulnerabilities = Vulnerability[];
/**
 * Producer-observed outcome for one enabled detector.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "DetectorRunStatus".
 */
export type DetectorRunStatus1 = "complete" | "partial" | "failed";

/**
 * agentd -> Form -> analyzer: one host, one collection cycle.
 */
export interface AssetReport {
  assets?: Assets;
  collected_at: CollectedAt;
  collection_runs?: CollectionRuns;
  detector_runs?: DetectorRuns;
  host: HostInfo;
  report_id: ReportId;
  scanner_version: ScannerVersion;
  source_agent_id?: SourceAgentId;
  source_target_id?: SourceTargetId;
  vulnerabilities?: Vulnerabilities;
}
/**
 * An installed software package detected on the host.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Package".
 */
export interface Package {
  asset_id: AssetId;
  ecosystem?: Ecosystem;
  install_path?: InstallPath;
  kind?: Kind;
  name: Name;
  parent_asset_id?: ParentAssetId;
  source?: Source;
  source_name?: SourceName;
  source_version?: SourceVersion;
  version: Version;
}
/**
 * A system service (daemon) and its current run state.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Service".
 */
export interface Service {
  asset_id: AssetId1;
  exec_path?: ExecPath;
  kind?: Kind1;
  name: Name1;
  parent_asset_id?: ParentAssetId1;
  status: Status;
}
/**
 * A listening network port and the process bound to it.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Port".
 */
export interface Port {
  asset_id: AssetId2;
  kind?: Kind2;
  listen_addr: ListenAddr;
  parent_asset_id?: ParentAssetId2;
  pid?: Pid;
  port: Port1;
  process_name?: ProcessName;
  proto: Proto;
}
/**
 * A running process observed on a live host.
 *
 * ``command_line`` is a producer-redacted display value.  Producers must not
 * send raw environment variables, passwords, tokens, connection strings, or
 * other secret-bearing arguments.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "ProcessAsset".
 */
export interface ProcessAsset {
  asset_id: AssetId3;
  command_line?: CommandLine;
  command_line_redacted?: CommandLineRedacted;
  container_id?: ContainerId;
  exe_path?: ExePath;
  executable_sha256?: ExecutableSha256;
  kind?: Kind3;
  name: Name2;
  parent_asset_id?: ParentAssetId3;
  pid: Pid1;
  ppid?: Ppid;
  started_at?: StartedAt;
  systemd_unit?: SystemdUnit;
  uid?: Uid;
  username?: Username;
}
/**
 * A listener enriched with process, service and workload ownership.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "NetworkService".
 */
export interface NetworkService {
  asset_id: AssetId4;
  container_id?: ContainerId1;
  exe_path?: ExePath1;
  executable_sha256?: ExecutableSha2561;
  kind?: Kind4;
  listen_addr: ListenAddr1;
  package_name?: PackageName;
  parent_asset_id?: ParentAssetId4;
  port: Port2;
  port_asset_id: PortAssetId;
  process_asset_id?: ProcessAssetId;
  process_name?: ProcessName1;
  proto: Proto1;
  service_asset_id?: ServiceAssetId;
  systemd_unit?: SystemdUnit1;
  uid?: Uid1;
  username?: Username1;
}
/**
 * A mounted filesystem and its security-relevant capacity/options.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "FilesystemMount".
 */
export interface FilesystemMount {
  asset_id: AssetId5;
  available_bytes?: AvailableBytes;
  available_inodes?: AvailableInodes;
  fs_type: FsType;
  kind?: Kind5;
  mount_point: MountPoint;
  options?: Options;
  parent_asset_id?: ParentAssetId5;
  readonly: Readonly;
  remote: Remote;
  source: Source1;
  total_bytes?: TotalBytes;
  total_inodes?: TotalInodes;
}
/**
 * A database, message broker, or cache discovered without reading data.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "DataService".
 */
export interface DataService {
  anonymous_access?: AnonymousAccess;
  asset_id: AssetId6;
  audit_enabled?: AuditEnabled;
  authentication_enabled?: AuthenticationEnabled;
  backup_enabled?: BackupEnabled;
  category: DataServiceCategory;
  config_paths?: ConfigPaths;
  data_paths?: DataPaths;
  discovery_source: DiscoverySource;
  endpoints?: Endpoints;
  engine: Engine;
  kind?: Kind6;
  network_service_ids?: NetworkServiceIds;
  object_coverage?: DataMetadataCoverage;
  objects?: Objects;
  parent_asset_id?: ParentAssetId6;
  principal_coverage?: DataMetadataCoverage;
  principals?: Principals;
  process_asset_id?: ProcessAssetId1;
  replication_enabled?: ReplicationEnabled;
  tls_enabled?: TlsEnabled;
  version?: Version1;
}
/**
 * Explicit catalog coverage; a complete zero is distinct from no access.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "DataMetadataCoverage".
 */
export interface DataMetadataCoverage {
  reason?: Reason;
  record_count?: RecordCount;
  status: DataMetadataStatus;
}
/**
 * Database/topic/queue metadata; records and messages are never included.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "DataObject".
 */
export interface DataObject {
  access_enabled?: AccessEnabled;
  acl_entry_count?: AclEntryCount;
  backlog_messages?: BacklogMessages;
  connection_limit?: ConnectionLimit;
  name: Name3;
  object_type: ObjectType;
  owner?: Owner;
  retention_seconds?: RetentionSeconds;
}
/**
 * Database/broker principal metadata without password material.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "DataPrincipal".
 */
export interface DataPrincipal {
  can_login?: CanLogin;
  member_of?: MemberOf;
  name: Name4;
  privileged?: Privileged;
  replication?: Replication;
}
/**
 * Firewall, MAC, audit, time-sync, or log-forwarding posture.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "SecurityControl".
 */
export interface SecurityControl {
  asset_id: AssetId7;
  control: SecurityControlType;
  details?: Details;
  kind?: Kind7;
  mode?: Mode;
  name: Name5;
  parent_asset_id?: ParentAssetId7;
  status: SecurityControlStatus;
}
/**
 * Metadata and digest for a security-sensitive file.
 *
 * File contents, ACL entries, password hashes and configuration values are
 * intentionally absent from this contract.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "SensitiveFile".
 */
export interface SensitiveFile {
  acl_risk?: AclRisk;
  asset_id: AssetId8;
  category: SensitiveFileCategory;
  group_writable: GroupWritable;
  kind?: Kind8;
  mode?: Mode1;
  modified_at?: ModifiedAt;
  owner_gid?: OwnerGid;
  owner_uid?: OwnerUid;
  parent_asset_id?: ParentAssetId8;
  path: Path;
  setgid: Setgid;
  setuid: Setuid;
  sha256?: Sha256;
  size_bytes?: SizeBytes;
  world_writable: WorldWritable;
}
/**
 * Metadata-only persistence entry with a redacted command summary.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "PersistenceEntry".
 */
export interface PersistenceEntry {
  asset_id: AssetId9;
  command?: Command;
  command_redacted?: CommandRedacted;
  content_sha256?: ContentSha256;
  enabled?: Enabled;
  entry_type: PersistenceType;
  kind?: Kind9;
  modified_at?: ModifiedAt1;
  name: Name6;
  parent_asset_id?: ParentAssetId9;
  principal?: Principal;
  risk_flags?: RiskFlags;
  source_path: SourcePath;
}
/**
 * A local user account present on the host.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Account".
 */
export interface Account {
  asset_id: AssetId10;
  kind?: Kind10;
  last_login?: LastLogin;
  parent_asset_id?: ParentAssetId10;
  shell?: Shell;
  uid?: Uid2;
  username: Username2;
}
/**
 * A credential artifact found on the host, referenced only by its public fingerprint.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Credential".
 */
export interface Credential {
  asset_id: AssetId11;
  credential_kind: CredentialKind;
  fingerprint: Fingerprint;
  kind?: Kind11;
  owner?: Owner1;
  parent_asset_id?: ParentAssetId11;
  path?: Path1;
}
/**
 * A container workload discovered from static runtime metadata.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Container".
 */
export interface Container {
  asset_id: AssetId12;
  config_path?: ConfigPath;
  container_id?: ContainerId2;
  image?: Image;
  kind?: Kind12;
  name: Name7;
  parent_asset_id?: ParentAssetId12;
  rootfs_path?: RootfsPath;
  runtime: Runtime;
  status?: Status1;
}
/**
 * A container image present in local runtime storage (a pulled image that
 * may never have run), discovered from static on-disk metadata.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Image".
 */
export interface Image1 {
  asset_id: AssetId13;
  created?: Created;
  image_id?: ImageId;
  kind?: Kind13;
  name: Name8;
  parent_asset_id?: ParentAssetId13;
  runtime: Runtime1;
  tags?: Tags;
}
/**
 * Endpoint security product and the protection state observed on a host.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "SecurityProduct".
 */
export interface SecurityProduct {
  asset_id: AssetId14;
  behavior_monitor?: BehaviorMonitor;
  cloud_protection?: CloudProtection;
  engine_version?: EngineVersion;
  ioav_protection?: IoavProtection;
  kind?: Kind14;
  last_full_scan_at?: LastFullScanAt;
  last_quick_scan_at?: LastQuickScanAt;
  mode?: Mode2;
  name: Name9;
  parent_asset_id?: ParentAssetId14;
  product_version?: ProductVersion;
  real_time_protection?: RealTimeProtection;
  signature_updated_at?: SignatureUpdatedAt;
  signature_version?: SignatureVersion;
  signatures_out_of_date?: SignaturesOutOfDate;
  status: Status2;
  tamper_protection?: TamperProtection;
  vendor: Vendor;
}
/**
 * Collection evidence that distinguishes a real zero from unknown coverage.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "CollectionRun".
 */
export interface CollectionRun {
  collector: CollectionKind;
  reason?: Reason1;
  record_count?: RecordCount1;
  status: CollectionRunStatus;
}
/**
 * Agent-declared execution evidence; absence differs from a zero finding run.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "DetectorRun".
 */
export interface DetectorRun {
  detector: DetectorKind;
  finding_count?: FindingCount;
  reason?: Reason2;
  status?: DetectorRunStatus;
}
/**
 * Identity and network metadata of the host an upload originates from.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "HostInfo".
 */
export interface HostInfo {
  arch?: Arch;
  boot_time?: BootTime;
  host_id: HostId;
  hostname: Hostname;
  ip_addrs?: IpAddrs;
  kernel?: Kernel;
  mac_addrs?: MacAddrs;
  os: Os;
}
/**
 * A vulnerability finding affecting a specific asset on a host.
 *
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Vulnerability".
 */
export interface Vulnerability {
  affected_asset_id: AffectedAssetId;
  cvss_score?: CvssScore;
  evidence?: Evidence;
  parent_asset_id?: ParentAssetId15;
  references?: References;
  severity: Severity;
  source: Source2;
  vuln_id: VulnId;
}
