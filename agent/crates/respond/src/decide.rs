//! Decision stage: map a [`Detection`] + policy to an [`Action`].
//!
//! In [`Mode::Monitor`] (the default) the answer is always [`Action::None`] — the
//! detection is still reported, but no active response is attempted.

use crate::config::{GuardConfig, Mode};
use crate::Detection;

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
    /// Deny the currently pending fanotify file-open permission request.
    ///
    /// This action is decided in the normal policy layer but must be executed
    /// synchronously by the on-access sensor while its event fd is still valid.
    BlockOpen {
        /// Path whose pending open should be denied.
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
    if !passes_common_gates(detection, config) {
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
        if let Some(dst_ip) = detection.response_ip() {
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

/// Decide whether an on-access malware hit may deny the pending open.
///
/// Kept separate from [`decide`] because only the fanotify sensor owns the
/// still-pending permission event needed to execute [`Action::BlockOpen`].
#[cfg(any(feature = "onaccess", test))]
pub(crate) fn decide_block_open(detection: &Detection, config: &GuardConfig) -> Action {
    if !passes_common_gates(detection, config) || !config.response.allow_block_open {
        return Action::None;
    }
    match detection {
        Detection::Malware { path, .. } => Action::BlockOpen { path: path.clone() },
        _ => Action::None,
    }
}

fn passes_common_gates(detection: &Detection, config: &GuardConfig) -> bool {
    config.mode == Mode::Enforce && detection.severity() >= config.response.severity_threshold
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)] // nested-field tweaks read clearer than full literals
    use super::*;
    use crate::config::GuardConfig;
    use agent_contract::{IndicatorType, Severity, TraceProto};

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
            proto: TraceProto::Tcp,
            src_ip: "10.0.0.2".into(),
            src_port: Some(1234),
            dst_ip: "203.0.113.5".into(),
            dst_port: Some(443),
            response_ip: Some("203.0.113.5".into()),
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

    #[test]
    fn non_ip_ioc_and_direction_ambiguous_ids_never_block_an_endpoint() {
        let mut cfg = GuardConfig::default();
        cfg.mode = Mode::Enforce;
        cfg.response.allow_netblock = true;

        let non_ip_ioc = Detection::Network {
            severity: Severity::Critical,
            proto: TraceProto::Tcp,
            src_ip: "10.0.0.2".into(),
            src_port: Some(1234),
            dst_ip: "203.0.113.5".into(),
            dst_port: Some(443),
            response_ip: None,
            indicator: "evil.example".into(),
            indicator_type: IndicatorType::Domain,
            category: "c2".into(),
            source: "feed".into(),
        };
        let ambiguous_ids = Detection::Ids {
            severity: Severity::Critical,
            signature_id: "GUARD-PORT-4444".into(),
            signature_name: "suspicious port".into(),
            proto: TraceProto::Tcp,
            src_ip: "198.51.100.23".into(),
            src_port: Some(54321),
            dst_ip: "10.0.0.2".into(),
            dst_port: Some(4444),
            response_ip: None,
        };

        assert_eq!(decide(&non_ip_ioc, &cfg), Action::None);
        assert_eq!(decide(&ambiguous_ids, &cfg), Action::None);
    }

    #[test]
    fn block_open_requires_explicit_gate_even_in_enforce_mode() {
        let mut cfg = GuardConfig::default();
        cfg.mode = Mode::Enforce;

        assert_eq!(
            decide_block_open(&malware(Severity::Critical), &cfg),
            Action::None
        );

        cfg.response.allow_block_open = true;
        assert_eq!(
            decide_block_open(&malware(Severity::Critical), &cfg),
            Action::BlockOpen {
                path: "/opt/app/bad.bin".into()
            }
        );
    }

    #[test]
    fn block_open_honors_monitor_mode_and_severity_threshold() {
        let mut cfg = GuardConfig::default();
        cfg.response.allow_block_open = true;
        assert_eq!(
            decide_block_open(&malware(Severity::Critical), &cfg),
            Action::None,
            "monitor mode always wins"
        );

        cfg.mode = Mode::Enforce;
        cfg.response.severity_threshold = Severity::Critical;
        assert_eq!(
            decide_block_open(&malware(Severity::High), &cfg),
            Action::None,
            "below-threshold hits must fail open"
        );
    }
}
