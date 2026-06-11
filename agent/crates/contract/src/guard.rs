//! Real-time protection (guard) contract — the `posture-guard` envelope.
//!
//! Mirrors `fusion.schemas.guard_event`. Unlike [`AssetReport`](crate::AssetReport)
//! (a host snapshot) and [`FlowBatch`](crate::FlowBatch) (observed flows), a
//! [`GuardEventBatch`] carries a stream of live detections **plus the response
//! action the endpoint took** — the detect → respond → report output of the
//! guard daemon.
//!
//! [`GuardEvent`] is an internally-tagged union keyed on `kind`, reusing the
//! shared [`Severity`](crate::Severity), [`IndicatorType`](crate::IndicatorType),
//! and [`FlowProto`](crate::FlowProto) types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{FlowProto, IndicatorType, Severity};

/// Response action the guard attempted for a detection.
///
/// `none` / `logged` are non-destructive (detection-only / monitor mode); the
/// rest are active responses gated behind enforce mode + per-action policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTaken {
    /// No action taken (pure detection).
    #[serde(rename = "none")]
    NoAction,
    /// Detection recorded only (monitor mode / gated-off enforcement).
    Logged,
    /// File moved to the quarantine vault.
    Quarantined,
    /// File open denied in real time (fanotify `FAN_DENY`).
    BlockedOpen,
    /// Outbound connection blocked (firewall drop rule).
    BlockedConnection,
    /// Process terminated.
    Killed,
    /// Process suspended (reversible).
    Suspended,
}

/// Result of an attempted response action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The action succeeded.
    Success,
    /// The action failed.
    Failure,
    /// The action partially applied.
    Partial,
}

/// Kind of file-integrity change observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FimChange {
    /// File created.
    Created,
    /// File contents modified.
    Modified,
    /// File deleted.
    Deleted,
    /// Metadata / permission change only.
    Metadata,
}

/// A monitored file changed (FIM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityEvent {
    /// Stable id for this event within the batch.
    pub event_id: String,
    /// When the event was observed.
    pub timestamp: DateTime<Utc>,
    /// Normalized severity.
    pub severity: Severity,
    /// Host the event originates from.
    pub host_id: String,
    /// Response action attempted.
    pub action_taken: ActionTaken,
    /// Result of the response action.
    pub outcome: Outcome,
    /// Path of the changed file.
    pub path: String,
    /// What kind of change occurred.
    pub change_type: FimChange,
    /// SHA-256 before the change, if known.
    pub hash_before: Option<String>,
    /// SHA-256 after the change, if known.
    pub hash_after: Option<String>,
}

/// An on-access scan flagged a file (e.g. a `posture-malware` signature hit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareEvent {
    /// Stable id for this event within the batch.
    pub event_id: String,
    /// When the event was observed.
    pub timestamp: DateTime<Utc>,
    /// Normalized severity.
    pub severity: Severity,
    /// Host the event originates from.
    pub host_id: String,
    /// Response action attempted.
    pub action_taken: ActionTaken,
    /// Result of the response action.
    pub outcome: Outcome,
    /// Path of the flagged file.
    pub path: String,
    /// Detection / signature name (e.g. `Eicar-Test-Signature`).
    pub signature: String,
    /// Scanner that produced the hit (e.g. `posture-malware`, the built-in signature scanner).
    pub source: String,
    /// PID that triggered the open, when known.
    pub process_id: Option<u32>,
}

/// A suspicious process / behavior was observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Stable id for this event within the batch.
    pub event_id: String,
    /// When the event was observed.
    pub timestamp: DateTime<Utc>,
    /// Normalized severity.
    pub severity: Severity,
    /// Host the event originates from.
    pub host_id: String,
    /// Response action attempted.
    pub action_taken: ActionTaken,
    /// Result of the response action.
    pub outcome: Outcome,
    /// Subject process id.
    pub pid: u32,
    /// Subject process name.
    pub process_name: String,
    /// Behavior class (e.g. `privilege_escalation`, `exe_deleted_running`).
    pub behavior: String,
    /// Identifier of the behavior rule that fired.
    pub rule_id: String,
    /// Short description of the suspicious pattern.
    pub evidence: Option<String>,
    /// Parent process id, when known.
    pub parent_pid: Option<u32>,
    /// Parent process name, when known.
    pub parent_name: Option<String>,
}

/// A live connection matched a threat-intel IOC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Stable id for this event within the batch.
    pub event_id: String,
    /// When the event was observed.
    pub timestamp: DateTime<Utc>,
    /// Normalized severity.
    pub severity: Severity,
    /// Host the event originates from.
    pub host_id: String,
    /// Response action attempted.
    pub action_taken: ActionTaken,
    /// Result of the response action.
    pub outcome: Outcome,
    /// Transport class of the connection.
    pub proto: FlowProto,
    /// Source IP address.
    pub src_ip: String,
    /// Source port, when applicable.
    pub src_port: Option<u16>,
    /// Destination IP address.
    pub dst_ip: String,
    /// Destination port, when applicable.
    pub dst_port: Option<u16>,
    /// The matched IOC value (IP / domain / JA3).
    pub indicator: String,
    /// Which kind of indicator matched.
    pub indicator_type: IndicatorType,
    /// IOC category (e.g. `c2`, `malware`).
    pub category: String,
    /// IOC feed that produced the match.
    pub source: String,
}

/// A packet / flow matched an IDS signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsEvent {
    /// Stable id for this event within the batch.
    pub event_id: String,
    /// When the event was observed.
    pub timestamp: DateTime<Utc>,
    /// Normalized severity.
    pub severity: Severity,
    /// Host the event originates from.
    pub host_id: String,
    /// Response action attempted.
    pub action_taken: ActionTaken,
    /// Result of the response action.
    pub outcome: Outcome,
    /// Rule SID.
    pub signature_id: String,
    /// Human-readable rule name.
    pub signature_name: String,
    /// Transport class of the matched traffic.
    pub proto: FlowProto,
    /// Source IP address.
    pub src_ip: String,
    /// Source port, when applicable.
    pub src_port: Option<u16>,
    /// Destination IP address.
    pub dst_ip: String,
    /// Destination port, when applicable.
    pub dst_port: Option<u16>,
}

/// Internally-tagged union of all guard event kinds (discriminator: `kind`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuardEvent {
    /// File-integrity change.
    Fim(FileIntegrityEvent),
    /// On-access malware detection.
    Malware(MalwareEvent),
    /// Suspicious process / behavior.
    Process(ProcessEvent),
    /// Network IOC match.
    Network(NetworkEvent),
    /// IDS signature match.
    Ids(IdsEvent),
}

/// posture-guard -> fusion: a batch of real-time protection events from one host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEventBatch {
    /// Unique id for this batch instance.
    pub batch_id: String,
    /// UTC timestamp when the batch was assembled.
    pub collected_at: DateTime<Utc>,
    /// Host the events originate from.
    pub host_id: String,
    /// Version string of the guard agent that produced the batch.
    pub agent_version: String,
    /// The protection events.
    pub events: Vec<GuardEvent>,
}
