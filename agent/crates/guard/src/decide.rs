//! Decision stage: map a [`Detection`] + policy to an [`Action`].
//!
//! In [`Mode::Monitor`] (the default) the answer is always [`Action::None`] — the
//! detection is still reported, but no active response is attempted.

use crate::config::{GuardConfig, Mode};
use crate::event::Detection;

/// A response action the engine may attempt for a detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No active response (monitor mode, below threshold, or no applicable action).
    None,
    /// Move a flagged file into the quarantine vault (never deletes).
    Quarantine {
        /// Path of the file to quarantine.
        path: String,
    },
    /// Insert a firewall drop rule for a destination IP.
    BlockConnection {
        /// Destination IP to block.
        dst_ip: String,
    },
    /// Terminate a process (scaffolded; gated off in the v1 enforce set).
    Kill {
        /// PID to terminate.
        pid: u32,
    },
}

/// Decide the response action for `detection` under `config`.
///
/// Returns [`Action::None`] unless: mode is [`Mode::Enforce`], severity meets the
/// configured threshold, and the matching per-action gate is enabled.
pub fn decide(detection: &Detection, config: &GuardConfig) -> Action {
    if config.mode != Mode::Enforce {
        return Action::None;
    }
    if detection.severity() < config.response.severity_threshold {
        return Action::None;
    }

    let policy = &config.response;
    if policy.allow_quarantine {
        if let Some(path) = detection.file_path() {
            return Action::Quarantine {
                path: path.to_string(),
            };
        }
    }
    if policy.allow_netblock {
        if let Some(dst_ip) = detection.dst_ip() {
            return Action::BlockConnection {
                dst_ip: dst_ip.to_string(),
            };
        }
    }
    if policy.allow_kill {
        if let Some(pid) = detection.pid() {
            return Action::Kill { pid };
        }
    }
    Action::None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)] // nested-field tweaks read clearer than full literals
    use super::*;
    use crate::config::GuardConfig;
    use agent_contract::{FlowProto, IndicatorType, Severity};

    fn malware(sev: Severity) -> Detection {
        Detection::Malware {
            severity: sev,
            path: "/opt/app/bad.bin".into(),
            signature: "X".into(),
            source: "clamav".into(),
            process_id: None,
        }
    }

    fn network(sev: Severity) -> Detection {
        Detection::Network {
            severity: sev,
            proto: FlowProto::Tcp,
            src_ip: "10.0.0.2".into(),
            src_port: Some(1234),
            dst_ip: "203.0.113.5".into(),
            dst_port: Some(443),
            indicator: "203.0.113.5".into(),
            indicator_type: IndicatorType::Ip,
            category: "c2".into(),
            source: "feed".into(),
        }
    }

    #[test]
    fn monitor_mode_never_acts() {
        let mut cfg = GuardConfig::default();
        cfg.response.allow_quarantine = true; // gate on, but mode is monitor
        assert_eq!(decide(&malware(Severity::Critical), &cfg), Action::None);
    }

    #[test]
    fn enforce_quarantines_when_gated_and_severe() {
        let mut cfg = GuardConfig::default();
        cfg.mode = Mode::Enforce;
        cfg.response.allow_quarantine = true;
        assert_eq!(
            decide(&malware(Severity::Critical), &cfg),
            Action::Quarantine {
                path: "/opt/app/bad.bin".into()
            }
        );
    }

    #[test]
    fn below_threshold_does_not_act() {
        let mut cfg = GuardConfig::default(); // threshold = High
        cfg.mode = Mode::Enforce;
        cfg.response.allow_quarantine = true;
        assert_eq!(decide(&malware(Severity::Low), &cfg), Action::None);
    }

    #[test]
    fn gate_off_does_not_act() {
        let mut cfg = GuardConfig::default();
        cfg.mode = Mode::Enforce;
        cfg.response.allow_netblock = false;
        assert_eq!(decide(&network(Severity::Critical), &cfg), Action::None);
    }

    #[test]
    fn enforce_blocks_connection_when_gated() {
        let mut cfg = GuardConfig::default();
        cfg.mode = Mode::Enforce;
        cfg.response.allow_netblock = true;
        assert_eq!(
            decide(&network(Severity::High), &cfg),
            Action::BlockConnection {
                dst_ip: "203.0.113.5".into()
            }
        );
    }
}
