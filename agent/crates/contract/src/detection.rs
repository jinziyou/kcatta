//! Internal SOC stage contract passed from detection producers to responders.
//!
//! Unlike the analyzer-facing models in this crate, [`Detection`] is not a wire
//! format and deliberately does not implement Serde serialization. A detection
//! carries the raw fact needed to decide and apply a response and to build the
//! reported [`crate::GuardEvent`] after the response outcome is known.

use crate::{FimChange, IndicatorType, Severity, TraceProto};

/// One internal detection produced for the response stage.
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
        /// Egress destination safe to consider for an automated network block.
        ///
        /// This is set only when an IP IOC matched `dst_ip`. Source-IP, domain,
        /// and JA3 matches deliberately leave it empty because the current
        /// responders enforce destination-oriented egress blocks.
        response_ip: Option<String>,
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
        /// Endpoint explicitly attributed by the IDS rule as safe to consider
        /// for automated blocking. Direction-ambiguous rules leave this empty.
        response_ip: Option<String>,
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

    /// IP subject to a connection block, if any.
    ///
    /// Network IOC and IDS detections expose only an egress destination
    /// explicitly attributed by the detector. Their raw source/destination
    /// fields remain available for reporting but do not authorize an action.
    pub fn response_ip(&self) -> Option<&str> {
        match self {
            Detection::Network { response_ip, .. } => response_ip.as_deref(),
            Detection::Ids { response_ip, .. } => response_ip.as_deref(),
            _ => None,
        }
    }

    /// Backward-compatible alias for [`Self::response_ip`].
    #[deprecated(note = "use response_ip(); raw dst_ip no longer authorizes a response")]
    pub fn dst_ip(&self) -> Option<&str> {
        self.response_ip()
    }

    /// PID subject to a process action (kill), if any.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Detection::Process { pid, .. } => Some(*pid),
            _ => None,
        }
    }
}
