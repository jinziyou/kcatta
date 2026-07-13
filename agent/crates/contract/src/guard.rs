//! Real-time protection (guard) contract — the `agent-respond` envelope.
//!
//! Mirrors `analyzer.schemas.guard_event`. Unlike [`AssetReport`](crate::AssetReport)
//! (a host snapshot) and [`TraceBatch`](crate::TraceBatch) (observed events), a
//! [`GuardEventBatch`] carries a stream of live detections **plus the response
//! action the endpoint took** — the detect → respond → report output of the
//! guard daemon.
//!
//! [`GuardEvent`] is an internally-tagged union keyed on `kind`, reusing the
//! shared [`Severity`](crate::Severity), [`IndicatorType`](crate::IndicatorType),
//! and [`TraceProto`](crate::TraceProto) types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::wire::{ensure_chars, ensure_items};
use crate::{
    bounded_correlation_id, bounded_wire_text, IndicatorType, Severity, TraceProto,
    WireContractError, WIRE_LIST_MAX_ITEMS, WIRE_STRING_MAX_CHARS,
};

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

/// An on-access scan flagged a file (e.g. a `kcatta-malware` signature hit).
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
    /// Scanner that produced the hit (e.g. `kcatta-malware`, the built-in signature scanner).
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
    pub proto: TraceProto,
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
    pub proto: TraceProto,
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

impl GuardEvent {
    /// Bound every Form `CorrelationIdentifier` carried by this event.
    ///
    /// File paths, evidence, IP addresses, and hashes retain their original
    /// values because the wire contract gives them separate, wider bounds.
    pub fn bound_correlation_ids(&mut self) {
        match self {
            GuardEvent::Fim(event) => {
                event.event_id = bounded_correlation_id(&event.event_id);
                event.host_id = bounded_correlation_id(&event.host_id);
            }
            GuardEvent::Malware(event) => {
                event.event_id = bounded_correlation_id(&event.event_id);
                event.host_id = bounded_correlation_id(&event.host_id);
                event.signature = bounded_correlation_id(&event.signature);
                event.source = bounded_correlation_id(&event.source);
            }
            GuardEvent::Process(event) => {
                event.event_id = bounded_correlation_id(&event.event_id);
                event.host_id = bounded_correlation_id(&event.host_id);
                event.process_name = bounded_correlation_id(&event.process_name);
                event.behavior = bounded_correlation_id(&event.behavior);
                event.rule_id = bounded_correlation_id(&event.rule_id);
            }
            GuardEvent::Network(event) => {
                event.event_id = bounded_correlation_id(&event.event_id);
                event.host_id = bounded_correlation_id(&event.host_id);
                event.indicator = bounded_correlation_id(&event.indicator);
                event.category = bounded_correlation_id(&event.category);
                event.source = bounded_correlation_id(&event.source);
            }
            GuardEvent::Ids(event) => {
                event.event_id = bounded_correlation_id(&event.event_id);
                event.host_id = bounded_correlation_id(&event.host_id);
                event.signature_id = bounded_correlation_id(&event.signature_id);
                event.signature_name = bounded_correlation_id(&event.signature_name);
            }
        }
    }

    /// Bound ordinary evidence text without modifying file paths or asset ids.
    pub fn bound_wire_text_fields(&mut self) {
        if let GuardEvent::Process(event) = self {
            if let Some(evidence) = &mut event.evidence {
                *evidence = bounded_wire_text(evidence);
            }
        }
    }

    /// Normalize ordinary event text and validate dedicated path fields.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        self.bound_correlation_ids();
        self.bound_wire_text_fields();
        match self {
            GuardEvent::Fim(event) => {
                ensure_chars("guard.fim.path", &event.path, WIRE_STRING_MAX_CHARS)?;
                bound_optional_text(&mut event.hash_before);
                bound_optional_text(&mut event.hash_after);
            }
            GuardEvent::Malware(event) => {
                ensure_chars("guard.malware.path", &event.path, WIRE_STRING_MAX_CHARS)?;
            }
            GuardEvent::Process(event) => {
                bound_optional_text(&mut event.parent_name);
            }
            GuardEvent::Network(event) => {
                event.src_ip = bounded_wire_text(&event.src_ip);
                event.dst_ip = bounded_wire_text(&event.dst_ip);
            }
            GuardEvent::Ids(event) => {
                event.src_ip = bounded_wire_text(&event.src_ip);
                event.dst_ip = bounded_wire_text(&event.dst_ip);
            }
        }
        Ok(())
    }
}

/// agent-respond -> Form -> analyzer: real-time protection events from one host.
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
    /// Authenticated Agent identity injected by Form. Agent-originated payloads
    /// leave this absent; Form must never trust a value supplied by the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_agent_id: Option<String>,
    /// Form target bound to `source_agent_id`; absent for legacy telemetry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_target_id: Option<String>,
    /// The protection events.
    pub events: Vec<GuardEvent>,
}

impl GuardEventBatch {
    /// Bound every Form `CorrelationIdentifier` carried by this guard batch.
    pub fn bound_correlation_ids(&mut self) {
        self.batch_id = bounded_correlation_id(&self.batch_id);
        self.host_id = bounded_correlation_id(&self.host_id);
        self.agent_version = bounded_correlation_id(&self.agent_version);
        if let Some(source_agent_id) = &mut self.source_agent_id {
            *source_agent_id = bounded_correlation_id(source_agent_id);
        }
        if let Some(source_target_id) = &mut self.source_target_id {
            *source_target_id = bounded_correlation_id(source_target_id);
        }
        for event in &mut self.events {
            event.bound_correlation_ids();
        }
    }

    /// Bound ordinary evidence text carried by events in this batch.
    pub fn bound_wire_text_fields(&mut self) {
        for event in &mut self.events {
            event.bound_wire_text_fields();
        }
    }

    /// Normalize all event fields representable in a guard envelope.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        self.batch_id = bounded_correlation_id(&self.batch_id);
        self.host_id = bounded_correlation_id(&self.host_id);
        self.agent_version = bounded_correlation_id(&self.agent_version);
        if let Some(source_agent_id) = &mut self.source_agent_id {
            *source_agent_id = bounded_correlation_id(source_agent_id);
        }
        if let Some(source_target_id) = &mut self.source_target_id {
            *source_target_id = bounded_correlation_id(source_target_id);
        }
        for event in &mut self.events {
            event.normalize_wire_fields()?;
        }
        Ok(())
    }

    /// Validate the event count for one Form envelope.
    pub fn validate_envelope_list_bounds(&self) -> Result<(), WireContractError> {
        ensure_items("guard.events", self.events.len(), WIRE_LIST_MAX_ITEMS)
    }
}

fn bound_optional_text(value: &mut Option<String>) {
    if let Some(value) = value {
        *value = bounded_wire_text(value);
    }
}
