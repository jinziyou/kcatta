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
export type FlowId = string;
/**
 * Identifies the vantage point that observed the flow (typically the collector host or interface)
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
 * This interface was referenced by `FlowBatch`'s JSON-Schema
 * via the `definition` "IndicatorType".
 */
export type IndicatorType = "ip" | "domain" | "ja3";
/**
 * Severity level of a finding, ordered from informational to critical.
 *
 * This interface was referenced by `FlowBatch`'s JSON-Schema
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
export type Flows = FlowEvent[];

/**
 * collector -> analyzer: a batch of flow events from one collector instance.
 */
export interface FlowBatch {
  batch_id: BatchId;
  collected_at: CollectedAt;
  collector_id: CollectorId;
  collector_version: CollectorVersion;
  flows?: Flows;
}
/**
 * A single observed network flow with traffic stats and any IOC matches.
 *
 * This interface was referenced by `FlowBatch`'s JSON-Schema
 * via the `definition` "FlowEvent".
 */
export interface FlowEvent {
  app_proto?: AppProto;
  bytes_recv: BytesRecv;
  bytes_sent: BytesSent;
  dns_query?: DnsQuery;
  dst_ip: DstIp;
  dst_port?: DstPort;
  end_ts: EndTs;
  flow_id: FlowId;
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
}
/**
 * One IOC hit observed on a flow.
 *
 * This interface was referenced by `FlowBatch`'s JSON-Schema
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

