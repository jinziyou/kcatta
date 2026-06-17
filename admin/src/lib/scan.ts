/**
 * Scan-orchestration types — hand-mirrored from analyzer's internal
 * `schemas/scan.py` (ScanTarget / ScanJob). These are analyzer-internal API models,
 * NOT agent wire contracts, so they are intentionally not generated under
 * `./schemas/`. Keep in sync with `analyzer/src/analyzer/schemas/scan.py`.
 */

export type Transport = "ssh" | "winrm" | "local";
export type CredentialMode = "managed_key" | "identity" | "none";
export type ScanCapability = "host" | "trace" | "guard";
export type ScanJobState = "pending" | "running" | "succeeded" | "failed";
/** Execution mode, derived from capability: host/trace = 单次, guard = 常驻. */
export type ScanMode = "oneshot" | "resident";

export interface ScanTarget {
  target_id: string;
  name: string;
  address: string;
  port: number;
  transport: Transport;
  credential_mode: CredentialMode;
  identity_path: string | null;
  created_at: string;
}

export interface ScanTargetInput {
  name: string;
  address: string;
  port?: number;
  transport?: Transport;
  credential_mode?: CredentialMode;
  identity_path?: string | null;
  /** One-time password to bootstrap a managed SSH key; never persisted server-side. */
  password?: string | null;
}

export interface ScanJobOptions {
  scan_target: string;
  malware: boolean;
  pcap: boolean;
  iface: string;
  duration: number;
  bpf: string;
}

export interface ScanResult {
  kind: ScanCapability;
  report_id: string | null;
  batch_id: string | null;
  host_id: string | null;
  pid: string | null;
  detail: string | null;
}

export interface ScanJob {
  job_id: string;
  target_id: string;
  address: string;
  capability: ScanCapability;
  /** Derived from capability server-side; absent on very old records. */
  mode?: ScanMode | null;
  state: ScanJobState;
  options: ScanJobOptions;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  result: ScanResult | null;
  error: string | null;
}

export interface TriggerScanRequest {
  target_id: string;
  capability: ScanCapability;
  options?: Partial<ScanJobOptions>;
}

// ---- access-credential management ------------------------------------------

/** A durable access credential (managed SSH key / identity path), no secret material. */
export interface CredentialInfo {
  credential_id: string;
  credential_mode: CredentialMode;
  address: string;
  port: number;
  key_path: string;
  exists: boolean;
  fingerprint: string | null;
  target_ids: string[];
  target_names: string[];
}

/** Optional one-time password for rotate/revoke when the current key no longer works. */
export interface CredentialActionRequest {
  password?: string | null;
}

export interface CredentialTestResult {
  ok: boolean;
  detail: string;
}

export interface CredentialRevokeResult {
  revoked: boolean;
  key_deleted: boolean;
  detail: string;
}

// ---- resident guard daemon lifecycle ---------------------------------------

export interface GuardLifecycleStatus {
  target_id: string;
  address: string;
  alive: boolean;
  supervisor: string;
  pid: string | null;
  detail: string;
}
