/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

/**
 * Which agent capability a scan deploys.
 *
 * This interface was referenced by `TriggerScanRequest`'s JSON-Schema
 * via the `definition` "ScanCapability".
 */
export type ScanCapability = "host" | "trace" | "guard";
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
export type TargetId = string;
/**
 * On-demand Microsoft Defender scan requested for a WinRM host job.
 *
 * This interface was referenced by `TriggerScanRequest`'s JSON-Schema
 * via the `definition` "WindowsDefenderScan".
 */
export type WindowsDefenderScan1 = "none" | "quick" | "full";

/**
 * POST /scans body.
 */
export interface TriggerScanRequest {
  capability: ScanCapability;
  options?: ScanJobOptions;
  target_id: TargetId;
}
/**
 * Per-scan knobs (capability-specific; unused ones ignored).
 *
 * This interface was referenced by `TriggerScanRequest`'s JSON-Schema
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
