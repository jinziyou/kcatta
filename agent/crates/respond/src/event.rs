//! `Detection` — the raw fact a sensor emits, before a response is decided.
//!
//! A detection carries everything needed to (a) decide and apply a response and
//! (b) build the reported [`agent_contract::GuardEvent`] once the response
//! outcome is known. The contract event adds `event_id`, `timestamp`,
//! `action_taken`, and `outcome`; those are not part of the raw detection.

use agent_contract::{FimChange, IndicatorType, Severity, TraceProto};

/// One detection produced by a sensor.
#[derive(Debug, Clone)]
pub enum Detection {
    /// A monitored file changed (FIM).
    Fim {
        /// Normalized severity.
        severity: Severity,
        /// Path of the changed file.
        path: String,
        /// Kind of change.
        change: FimChange,
        /// SHA-256 before the change, if known.
        hash_before: Option<String>,
        /// SHA-256 after the change, if known.
        hash_after: Option<String>,
    },
    /// An on-access scan flagged a file.
    Malware {
        /// Normalized severity.
        severity: Severity,
        /// Path of the flagged file.
        path: String,
        /// Detection / signature name.
        signature: String,
        /// Scanner that produced the hit (e.g. `kcatta-malware`).
        source: String,
        /// PID that triggered the open, when known.
        process_id: Option<u32>,
    },
    /// A suspicious process / behavior.
    Process {
        /// Normalized severity.
        severity: Severity,
        /// Subject process id.
        pid: u32,
        /// Subject process name.
        process_name: String,
        /// Behavior class.
        behavior: String,
        /// Behavior rule id that fired.
        rule_id: String,
        /// Short evidence string.
        evidence: Option<String>,
        /// Parent process id, when known.
        parent_pid: Option<u32>,
        /// Parent process name, when known.
        parent_name: Option<String>,
    },
    /// A live connection matched a threat-intel IOC.
    Network {
        /// Normalized severity.
        severity: Severity,
        /// Transport class.
        proto: TraceProto,
        /// Source IP.
        src_ip: String,
        /// Source port.
        src_port: Option<u16>,
        /// Destination IP.
        dst_ip: String,
        /// Destination port.
        dst_port: Option<u16>,
        /// Matched IOC value.
        indicator: String,
        /// Kind of indicator.
        indicator_type: IndicatorType,
        /// IOC category.
        category: String,
        /// IOC feed source.
        source: String,
    },
    /// A packet / flow matched an IDS signature.
    Ids {
        /// Normalized severity.
        severity: Severity,
        /// Rule SID.
        signature_id: String,
        /// Human-readable rule name.
        signature_name: String,
        /// Transport class.
        proto: TraceProto,
        /// Source IP.
        src_ip: String,
        /// Source port.
        src_port: Option<u16>,
        /// Destination IP.
        dst_ip: String,
        /// Destination port.
        dst_port: Option<u16>,
    },
}

impl Detection {
    /// Severity carried by this detection.
    pub fn severity(&self) -> Severity {
        match self {
            Detection::Fim { severity, .. }
            | Detection::Malware { severity, .. }
            | Detection::Process { severity, .. }
            | Detection::Network { severity, .. }
            | Detection::Ids { severity, .. } => *severity,
        }
    }

    /// File path subject to a file action (quarantine), if any.
    pub fn file_path(&self) -> Option<&str> {
        match self {
            Detection::Malware { path, .. } => Some(path),
            _ => None,
        }
    }

    /// Destination IP subject to a connection block, if any.
    pub fn dst_ip(&self) -> Option<&str> {
        match self {
            Detection::Network { dst_ip, .. } | Detection::Ids { dst_ip, .. } => Some(dst_ip),
            _ => None,
        }
    }

    /// PID subject to a process action (kill), if any.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Detection::Process { pid, .. } => Some(*pid),
            _ => None,
        }
    }
}
