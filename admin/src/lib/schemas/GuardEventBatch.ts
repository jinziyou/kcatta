/**
 * AUTO-GENERATED — do not edit.
 *
 * Source: form/schemas-json/*.schema.json (the public control-plane contract).
 * Regenerate: `pnpm generate:contracts` from admin/
 */

export type AgentVersion = string;
export type BatchId = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type CollectedAt = string;
/**
 * The response action the guard attempted for a detection.
 *
 * `none` / `logged` are non-destructive (detection-only / monitor mode); the
 * rest are active responses gated behind enforce mode + per-action policy.
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "ActionTaken".
 */
export type ActionTaken =
  | "none"
  | "logged"
  | "quarantined"
  | "blocked_open"
  | "blocked_connection"
  | "killed"
  | "suspended";
/**
 * Kind of file-integrity change observed.
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "FimChange".
 */
export type FimChange = "created" | "modified" | "deleted" | "metadata";
/**
 * Stable id for this event within the batch
 */
export type EventId = string;
/**
 * SHA-256 after the change, if known
 */
export type HashAfter = string | null;
/**
 * SHA-256 before the change, if known
 */
export type HashBefore = string | null;
export type HostId = string;
export type Kind = "fim";
/**
 * Result of an attempted response action.
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "Outcome".
 */
export type Outcome = "success" | "failure" | "partial";
export type Path = string;
/**
 * Severity level of a finding, ordered from informational to critical.
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "Severity".
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type Timestamp = string;
/**
 * Stable id for this event within the batch
 */
export type EventId1 = string;
export type HostId1 = string;
export type Kind1 = "malware";
export type Path1 = string;
/**
 * PID that triggered the open
 */
export type ProcessId = number | null;
/**
 * Detection / signature name, e.g. 'EICAR-Test-File'
 */
export type Signature = string;
/**
 * Scanner that produced the hit, e.g. 'kcatta-malware'
 */
export type Source = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type Timestamp1 = string;
/**
 * Behavior class, e.g. 'privilege_escalation', 'exe_deleted_running'
 */
export type Behavior = string;
/**
 * Stable id for this event within the batch
 */
export type EventId2 = string;
export type Evidence = string | null;
export type HostId2 = string;
export type Kind2 = "process";
export type ParentName = string | null;
export type ParentPid = number | null;
export type Pid = number;
export type ProcessName = string;
/**
 * Identifier of the behavior rule that fired
 */
export type RuleId = string;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type Timestamp2 = string;
/**
 * IOC category, e.g. 'c2', 'malware'
 */
export type Category = string;
export type DstIp = string;
export type DstPort = number | null;
/**
 * Stable id for this event within the batch
 */
export type EventId3 = string;
export type HostId3 = string;
/**
 * The matched IOC value (IP / domain / JA3)
 */
export type Indicator = string;
/**
 * Type of indicator of compromise that was matched.
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "IndicatorType".
 */
export type IndicatorType = "ip" | "domain" | "ja3";
export type Kind3 = "network";
export type Proto = "tcp" | "udp" | "icmp" | "other";
/**
 * IOC feed that produced the match
 */
export type Source1 = string;
export type SrcIp = string;
export type SrcPort = number | null;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type Timestamp3 = string;
export type DstIp1 = string;
export type DstPort1 = number | null;
/**
 * Stable id for this event within the batch
 */
export type EventId4 = string;
export type HostId4 = string;
export type Kind4 = "ids";
export type Proto1 = "tcp" | "udp" | "icmp" | "other";
/**
 * Rule SID
 */
export type SignatureId = string;
export type SignatureName = string;
export type SrcIp1 = string;
export type SrcPort1 = number | null;
/**
 * UTC timestamp encoded as RFC 3339 / ISO 8601
 */
export type Timestamp4 = string;
/**
 * @maxItems 4096
 */
export type Events = (FileIntegrityEvent | MalwareEvent | ProcessEvent | NetworkEvent | IdsEvent)[];
export type HostId5 = string;
/**
 * Authenticated Agent identity injected by Form; never trusted from payload
 */
export type SourceAgentId = string | null;
/**
 * Form target bound to source_agent_id; absent for legacy data
 */
export type SourceTargetId = string | null;

/**
 * agent-respond -> Form -> analyzer: protection events from one host.
 */
export interface GuardEventBatch {
  agent_version: AgentVersion;
  batch_id: BatchId;
  collected_at: CollectedAt;
  events?: Events;
  host_id: HostId5;
  source_agent_id?: SourceAgentId;
  source_target_id?: SourceTargetId;
}
/**
 * A monitored file changed (FIM).
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "FileIntegrityEvent".
 */
export interface FileIntegrityEvent {
  action_taken: ActionTaken;
  change_type: FimChange;
  event_id: EventId;
  hash_after?: HashAfter;
  hash_before?: HashBefore;
  host_id: HostId;
  kind?: Kind;
  outcome: Outcome;
  path: Path;
  severity: Severity;
  timestamp: Timestamp;
}
/**
 * An on-access scan flagged a file.
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "MalwareEvent".
 */
export interface MalwareEvent {
  action_taken: ActionTaken;
  event_id: EventId1;
  host_id: HostId1;
  kind?: Kind1;
  outcome: Outcome;
  path: Path1;
  process_id?: ProcessId;
  severity: Severity;
  signature: Signature;
  source: Source;
  timestamp: Timestamp1;
}
/**
 * A suspicious process / behavior was observed.
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "ProcessEvent".
 */
export interface ProcessEvent {
  action_taken: ActionTaken;
  behavior: Behavior;
  event_id: EventId2;
  evidence?: Evidence;
  host_id: HostId2;
  kind?: Kind2;
  outcome: Outcome;
  parent_name?: ParentName;
  parent_pid?: ParentPid;
  pid: Pid;
  process_name: ProcessName;
  rule_id: RuleId;
  severity: Severity;
  timestamp: Timestamp2;
}
/**
 * A live connection matched a threat-intel IOC.
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "NetworkEvent".
 */
export interface NetworkEvent {
  action_taken: ActionTaken;
  category: Category;
  dst_ip: DstIp;
  dst_port?: DstPort;
  event_id: EventId3;
  host_id: HostId3;
  indicator: Indicator;
  indicator_type: IndicatorType;
  kind?: Kind3;
  outcome: Outcome;
  proto: Proto;
  severity: Severity;
  source: Source1;
  src_ip: SrcIp;
  src_port?: SrcPort;
  timestamp: Timestamp3;
}
/**
 * A packet / flow matched an IDS signature.
 *
 * This interface was referenced by `GuardEventBatch`'s JSON-Schema
 * via the `definition` "IdsEvent".
 */
export interface IdsEvent {
  action_taken: ActionTaken;
  dst_ip: DstIp1;
  dst_port?: DstPort1;
  event_id: EventId4;
  host_id: HostId4;
  kind?: Kind4;
  outcome: Outcome;
  proto: Proto1;
  severity: Severity;
  signature_id: SignatureId;
  signature_name: SignatureName;
  src_ip: SrcIp1;
  src_port?: SrcPort1;
  timestamp: Timestamp4;
}
