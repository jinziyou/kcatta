/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: analyzer/schemas-json/*.schema.json (derived from Pydantic models).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type BatchId = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CollectedAt = string;
export type CollectorId = string;
export type CollectorVersion = string;
/**
 * Detected application protocol: HTTP / DNS / TLS / SSH / ...
 */
export type AppProto = string | null;
export type BytesRecv = number;
export type BytesSent = number;
export type DnsQuery = string | null;
export type DstIp = string;
export type DstPort = number | null;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type EndTs = string;
/**
 * Identifies the vantage point that observed the trace (typically the collector host or interface)
 */
export type HostId = string;
/**
 * JA3 TLS client fingerprint
 */
export type Ja3 = string | null;
export type PacketsRecv = number;
export type PacketsSent = number;
export type Proto = "tcp" | "udp" | "icmp" | "other";
export type SrcIp = string;
export type SrcPort = number | null;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type StartTs = string;
/**
 * Threat category, e.g. 'c2', 'malware', 'phishing', 'tor-exit', 'scanner'
 */
export type Category = string;
export type Description = string | null;
/**
 * The matched IOC value (IP / domain / JA3 hash)
 */
export type Indicator = string;
/**
 * Type of indicator of compromise that was matched.
 *
 * This interface was referenced by `TraceBatch`'s JSON-Schema
 * via the `definition` "IndicatorType".
 */
export type IndicatorType = "ip" | "domain" | "ja3";
/**
 * Severity level of a finding, ordered from informational to critical.
 *
 * This interface was referenced by `TraceBatch`'s JSON-Schema
 * via the `definition` "Severity".
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";
/**
 * Name of the IOC feed that produced the match
 */
export type Source = string;
/**
 * IOC matches found by collector-side preliminary processing
 */
export type ThreatIntel = ThreatMatch[];
export type TlsSni = string | null;
export type TraceId = string;
/**
 * Network traces (5-tuple flows + IOC matches).
 */
export type Events = TraceEvent[];
/**
 * Short process name (kernel TASK_COMM, <=16 bytes).
 */
export type Comm = string;
/**
 * Vantage point that observed the operation.
 */
export type HostId1 = string;
export type Op = "open" | "create" | "write" | "unlink" | "rename" | "chmod" | "link" | "symlink" | "mkdir";
/**
 * Primary target path of the operation.
 */
export type Path = string;
/**
 * PID of the process performing the operation.
 */
export type Pid = number;
/**
 * Syscall return value (fd or -errno) when captured.
 */
export type Ret = number | null;
/**
 * Second path for link / rename operations.
 */
export type TargetPath = string | null;
/**
 * IOC matches (known-bad path / hash) from collector-side processing.
 */
export type ThreatIntel1 = ThreatMatch[];
export type TraceId1 = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type Ts = string;
/**
 * Acting user id when known.
 */
export type Uid = number | null;
/**
 * File-system operations observed by the eBPF tracer.
 */
export type FileEvents = FileTraceEvent[];
/**
 * Command-line arguments for exec events.
 */
export type Argv = string[];
/**
 * cgroup / container id for workload attribution.
 */
export type Cgroup = string | null;
/**
 * Short process name (kernel TASK_COMM, <=16 bytes).
 */
export type Comm1 = string;
export type EventType = "exec" | "exit";
/**
 * Resolved executable path for exec events.
 */
export type Exe = string | null;
/**
 * Exit code for exit events.
 */
export type ExitCode = number | null;
/**
 * Vantage point that observed the event.
 */
export type HostId2 = string;
export type Pid1 = number;
/**
 * Parent PID when known.
 */
export type Ppid = number | null;
/**
 * IOC matches (known-bad binary hash / name) from collector-side processing.
 */
export type ThreatIntel2 = ThreatMatch[];
export type TraceId2 = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type Ts1 = string;
/**
 * Acting user id when known.
 */
export type Uid1 = number | null;
/**
 * Process exec/exit events observed by the eBPF tracer.
 */
export type ProcessEvents = ProcessTraceEvent[];

/**
 * collector -> analyzer: a batch of trace events from one collector instance.
 *
 * Carries three homogeneous streams from one eBPF collection cycle: network
 * traces (5-tuple flows), file operations, and process lifecycle events.
 */
export interface TraceBatch {
  batch_id: BatchId;
  collected_at: CollectedAt;
  collector_id: CollectorId;
  collector_version: CollectorVersion;
  events?: Events;
  file_events?: FileEvents;
  process_events?: ProcessEvents;
}
/**
 * A single observed network trace with traffic stats and any IOC matches.
 *
 * This interface was referenced by `TraceBatch`'s JSON-Schema
 * via the `definition` "TraceEvent".
 */
export interface TraceEvent {
  app_proto?: AppProto;
  bytes_recv: BytesRecv;
  bytes_sent: BytesSent;
  dns_query?: DnsQuery;
  dst_ip: DstIp;
  dst_port?: DstPort;
  end_ts: EndTs;
  host_id: HostId;
  ja3?: Ja3;
  packets_recv?: PacketsRecv;
  packets_sent?: PacketsSent;
  proto: Proto;
  src_ip: SrcIp;
  src_port?: SrcPort;
  start_ts: StartTs;
  threat_intel?: ThreatIntel;
  tls_sni?: TlsSni;
  trace_id: TraceId;
}
/**
 * One IOC hit observed on a flow.
 *
 * This interface was referenced by `TraceBatch`'s JSON-Schema
 * via the `definition` "ThreatMatch".
 */
export interface ThreatMatch {
  category: Category;
  description?: Description;
  indicator: Indicator;
  indicator_type: IndicatorType;
  severity: Severity;
  source: Source;
}
/**
 * A single file-system operation observed by the eBPF tracer.
 *
 * Captured from kernel tracepoints / LSM hooks (open, write, unlink, rename,
 * chmod, ...) and attributed to the process that performed it.
 *
 * This interface was referenced by `TraceBatch`'s JSON-Schema
 * via the `definition` "FileTraceEvent".
 */
export interface FileTraceEvent {
  comm: Comm;
  host_id: HostId1;
  op: Op;
  path: Path;
  pid: Pid;
  ret?: Ret;
  target_path?: TargetPath;
  threat_intel?: ThreatIntel1;
  trace_id: TraceId1;
  ts: Ts;
  uid?: Uid;
}
/**
 * A process lifecycle event observed by the eBPF tracer.
 *
 * Captured from sched_process_exec / sched_process_exit tracepoints: program
 * invocations (execve) and their exits, with parent and cgroup attribution.
 *
 * This interface was referenced by `TraceBatch`'s JSON-Schema
 * via the `definition` "ProcessTraceEvent".
 */
export interface ProcessTraceEvent {
  argv?: Argv;
  cgroup?: Cgroup;
  comm: Comm1;
  event_type: EventType;
  exe?: Exe;
  exit_code?: ExitCode;
  host_id: HostId2;
  pid: Pid1;
  ppid?: Ppid;
  threat_intel?: ThreatIntel2;
  trace_id: TraceId2;
  ts: Ts1;
  uid?: Uid1;
}

