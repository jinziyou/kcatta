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
export type Iface = string;
/**
 * host: also run the built-in malware scan
 */
export type Malware = boolean;
/**
 * trace: use custom libpcap build instead of live connection-table capture
 */
export type Pcap = boolean;
/**
 * host: -t object (host|all|...)
 */
export type ScanTarget = string;
export type TargetId = string;

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
  iface?: Iface;
  malware?: Malware;
  pcap?: Pcap;
  scan_target?: ScanTarget;
}
