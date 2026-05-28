/**
 * TypeScript mirror of the cyber-posture data contract.
 *
 * The authoritative source is the Pydantic package at
 * `form/src/form/schemas/`. The JSON Schema artifacts under
 * `form/schemas-json/` are derived from there.
 *
 * These types are hand-written rather than generated -- the surface is
 * small and codegen tools (json-schema-to-typescript) emit awkward
 * tagged unions for discriminated unions. If the contract grows, swap
 * this file for generated output.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type AssetKind = "package" | "service" | "port" | "account" | "credential";

export interface BaseAsset {
  asset_id: string;
}

export interface Package extends BaseAsset {
  kind: "package";
  name: string;
  version: string;
  source: string | null;
  install_path: string | null;
}

export interface Service extends BaseAsset {
  kind: "service";
  name: string;
  status: string;
  exec_path: string | null;
}

export interface Port extends BaseAsset {
  kind: "port";
  proto: "tcp" | "udp";
  port: number;
  listen_addr: string;
  process_name: string | null;
  pid: number | null;
}

export interface Account extends BaseAsset {
  kind: "account";
  username: string;
  uid: number | null;
  shell: string | null;
  last_login: string | null;
}

export interface Credential extends BaseAsset {
  kind: "credential";
  credential_kind: "ssh_key" | "api_key" | "password" | "token";
  fingerprint: string;
  path: string | null;
  owner: string | null;
}

export type Asset = Package | Service | Port | Account | Credential;

export interface Vulnerability {
  vuln_id: string;
  severity: Severity;
  cvss_score: number | null;
  affected_asset_id: string;
  source: string;
  evidence: string | null;
  references: string[];
}

export interface HostInfo {
  host_id: string;
  hostname: string;
  os: string;
  kernel: string | null;
  arch: string | null;
  ip_addrs: string[];
  mac_addrs: string[];
  boot_time: string | null;
}

export interface AssetReport {
  report_id: string;
  collected_at: string;
  scanner_version: string;
  host: HostInfo;
  assets: Asset[];
  vulnerabilities: Vulnerability[];
}
