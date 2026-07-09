//! Agent **detect** layer: local finding engines (no CVE / no upload).
//!
//! - [`posture`] — sshd_config / shadow / SUID misconfigurations
//! - [`secrets`] — credential-leak findings (privacy-safe evidence only)
//! - [`ioc`] — ThreatFeed load / match / enrich for TraceEvent
//! - [`malware`] — re-export of [`agent_detect_malware`]
//!
//! Collectors that implement `agent_collect_host::Collector` stay in `agent-collect-host` and
//! call these engines with a scan root + `host_id`.
//!
//! CVE matching stays in the Python analyzer.

pub mod ioc;
pub mod posture;
pub mod secrets;

pub use agent_detect_malware as malware;
