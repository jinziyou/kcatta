/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (derived from Pydantic models).
 * Regenerate: `pnpm generate:contracts` from portal/
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
 * Package manager, e.g. apt / yum / pip / npm
 */
export type Source = string | null;
export type Version = string;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId1 = string;
export type ExecPath = string | null;
export type Kind1 = "service";
export type Name1 = string;
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
export type Pid = number | null;
export type Port1 = number;
export type ProcessName = string | null;
export type Proto = "tcp" | "udp";
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId3 = string;
export type Kind3 = "account";
export type LastLogin = string | null;
export type Shell = string | null;
export type Uid = number | null;
export type Username = string;
/**
 * Stable identifier assigned by the scanner
 */
export type AssetId4 = string;
/**
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "CredentialKind".
 */
export type CredentialKind = "ssh_key" | "api_key" | "password" | "token";
/**
 * Public fingerprint or hash; the secret itself MUST NEVER be transmitted
 */
export type Fingerprint = string;
export type Kind4 = "credential";
export type Owner = string | null;
export type Path = string | null;
export type Assets = (Package | Service | Port | Account | Credential)[];
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CollectedAt = string;
export type Arch = string | null;
export type BootTime = string | null;
export type HostId = string;
export type Hostname = string;
export type IpAddrs = string[];
export type Kernel = string | null;
export type MacAddrs = string[];
/**
 * OS family + version, e.g. 'Ubuntu 22.04'
 */
export type Os = string;
export type ReportId = string;
export type ScannerVersion = string;
/**
 * References Asset.asset_id from the same report
 */
export type AffectedAssetId = string;
export type CvssScore = number | null;
/**
 * Short, human-readable proof (e.g. matched package version)
 */
export type Evidence = string | null;
export type References = string[];
/**
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Severity".
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";
/**
 * Scanner / engine that produced the finding
 */
export type Source1 = string;
/**
 * CVE id, vendor advisory id, or scanner-local id (e.g. GHSA-..., CVE-2024-1234)
 */
export type VulnId = string;
export type Vulnerabilities = Vulnerability[];

/**
 * scanner -> form: one host, one collection cycle.
 */
export interface AssetReport {
  assets?: Assets;
  collected_at: CollectedAt;
  host: HostInfo;
  report_id: ReportId;
  scanner_version: ScannerVersion;
  vulnerabilities?: Vulnerabilities;
}
/**
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Package".
 */
export interface Package {
  asset_id: AssetId;
  ecosystem?: Ecosystem;
  install_path?: InstallPath;
  kind?: Kind;
  name: Name;
  source?: Source;
  version: Version;
}
/**
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Service".
 */
export interface Service {
  asset_id: AssetId1;
  exec_path?: ExecPath;
  kind?: Kind1;
  name: Name1;
  status: Status;
}
/**
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Port".
 */
export interface Port {
  asset_id: AssetId2;
  kind?: Kind2;
  listen_addr: ListenAddr;
  pid?: Pid;
  port: Port1;
  process_name?: ProcessName;
  proto: Proto;
}
/**
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Account".
 */
export interface Account {
  asset_id: AssetId3;
  kind?: Kind3;
  last_login?: LastLogin;
  shell?: Shell;
  uid?: Uid;
  username: Username;
}
/**
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Credential".
 */
export interface Credential {
  asset_id: AssetId4;
  credential_kind: CredentialKind;
  fingerprint: Fingerprint;
  kind?: Kind4;
  owner?: Owner;
  path?: Path;
}
/**
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
 * This interface was referenced by `AssetReport`'s JSON-Schema
 * via the `definition` "Vulnerability".
 */
export interface Vulnerability {
  affected_asset_id: AffectedAssetId;
  cvss_score?: CvssScore;
  evidence?: Evidence;
  references?: References;
  severity: Severity;
  source: Source1;
  vuln_id: VulnId;
}

