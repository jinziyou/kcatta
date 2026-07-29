/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type Address = string;
/**
 * Number of execution attempts claimed
 */
export type Attempt = number;
/**
 * Earliest time the durable worker may claim a pending/retrying job
 */
export type AvailableAt = string | null;
export type CancelRequestedAt = string | null;
/**
 * Which agent capability a scan deploys.
 *
 * This interface was referenced by `ScanJob`'s JSON-Schema
 * via the `definition` "ScanCapability".
 */
export type ScanCapability = "host" | "trace" | "guard";
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CreatedAt = string;
export type Error = string | null;
export type FinishedAt = string | null;
export type JobId = string;
export type MaxAttempts = number;
/**
 * How a detection runs — surfaced explicitly so admin can choose up front.
 *
 * Derived from the capability rather than requested independently: ``host`` /
 * ``trace`` run once and finish (``oneshot``); ``guard`` deploys a long-lived
 * daemon that keeps detecting and streaming events (``resident``).
 *
 * This interface was referenced by `ScanJob`'s JSON-Schema
 * via the `definition` "ScanMode".
 */
export type ScanMode = "oneshot" | "resident";
export type Bpf = string;
export type Duration = number;
/**
 * trace: collect file/process eBPF events
 */
export type Ebpf = boolean;
/**
 * guard: enable network IOC and IDS
 */
export type GuardNetwork = boolean;
/**
 * guard: enable on-access malware scanning when the build supports it
 */
export type GuardOnaccess = boolean;
export type Iface = string;
/**
 * trace: use Form's managed IOC feed
 */
export type Intel = boolean;
/**
 * host: run configured malware signatures
 */
export type Malware = boolean;
/**
 * trace: use custom libpcap build instead of live connection-table capture
 */
export type Pcap = boolean;
/**
 * host: run security-posture checks
 */
export type Posture = boolean;
/**
 * host: upload scope (host|all)
 */
export type ScanTarget = string;
/**
 * host: scan for leaked secret fingerprints
 */
export type Secrets = boolean;
/**
 * WinRM host: reuse Microsoft Defender (none collects existing history only; quick/full also starts that on-demand scan)
 */
export type WindowsDefenderScan = "none" | "quick" | "full";
export type BatchId = string | null;
export type DerivedAttempts = number;
export type DerivedReason = string | null;
export type DerivedRecords = number;
/**
 * Analyzer work that continues after the raw artifact was accepted.
 *
 * This interface was referenced by `ScanJob`'s JSON-Schema
 * via the `definition` "DerivedState".
 */
export type DerivedState = "pending" | "processing" | "complete" | "partial";
export type DerivedTruncated = boolean;
export type DerivedUpdatedAt = string | null;
export type Detail = string | null;
export type HostId = string | null;
export type Pid = string | null;
export type ReportId = string | null;
export type StartedAt = string | null;
/**
 * Lifecycle of a triggered scan job.
 */
export type ScanJobState = "pending" | "retrying" | "running" | "cancelling" | "succeeded" | "failed" | "cancelled";
export type TargetId = string;
export type UpdatedAt = string | null;
/**
 * Lifecycle of a triggered scan job.
 *
 * This interface was referenced by `ScanJob`'s JSON-Schema
 * via the `definition` "ScanJobState".
 */
export type ScanJobState1 = "pending" | "retrying" | "running" | "cancelling" | "succeeded" | "failed" | "cancelled";
/**
 * On-demand Microsoft Defender scan requested for a WinRM host job.
 *
 * This interface was referenced by `ScanJob`'s JSON-Schema
 * via the `definition` "WindowsDefenderScan".
 */
export type WindowsDefenderScan1 = "none" | "quick" | "full";

/**
 * A triggered scan and its durable worker lifecycle/result.
 *
 * Public job data deliberately excludes the worker's lease token and fencing
 * epoch. Those coordination fields stay in Form's private job repository;
 * Admin only sees useful scheduling state and attempt metadata.
 */
export interface ScanJob {
  address: Address;
  attempt?: Attempt;
  available_at?: AvailableAt;
  cancel_requested_at?: CancelRequestedAt;
  capability: ScanCapability;
  created_at: CreatedAt;
  error?: Error;
  finished_at?: FinishedAt;
  job_id: JobId;
  max_attempts?: MaxAttempts;
  mode?: ScanMode | null;
  options?: ScanJobOptions;
  result?: ScanResult | null;
  started_at?: StartedAt;
  state?: ScanJobState;
  target_id: TargetId;
  updated_at?: UpdatedAt;
}
/**
 * Per-scan knobs (capability-specific; unused ones ignored).
 *
 * This interface was referenced by `ScanJob`'s JSON-Schema
 * via the `definition` "ScanJobOptions".
 */
export interface ScanJobOptions {
  bpf?: Bpf;
  duration?: Duration;
  ebpf?: Ebpf;
  guard_network?: GuardNetwork;
  guard_onaccess?: GuardOnaccess;
  iface?: Iface;
  intel?: Intel;
  malware?: Malware;
  pcap?: Pcap;
  posture?: Posture;
  scan_target?: ScanTarget;
  secrets?: Secrets;
  windows_defender_scan?: WindowsDefenderScan;
}
/**
 * Reference to the artifact a finished scan produced (for admin to fetch).
 *
 * This interface was referenced by `ScanJob`'s JSON-Schema
 * via the `definition` "ScanResult".
 */
export interface ScanResult {
  batch_id?: BatchId;
  derived_attempts?: DerivedAttempts;
  derived_reason?: DerivedReason;
  derived_records?: DerivedRecords;
  /**
   * Analyzer detection/correlation state; absent for resident Guard results
   */
  derived_state?: DerivedState | null;
  derived_truncated?: DerivedTruncated;
  derived_updated_at?: DerivedUpdatedAt;
  detail?: Detail;
  host_id?: HostId;
  kind: ScanCapability;
  pid?: Pid;
  report_id?: ReportId;
}
