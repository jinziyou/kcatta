//! Agent **detect** layer: local finding engines (no CVE / no upload).
//!
//! - [`Detection`] — re-export of the internal `agent-contract` stage type emitted for Respond
//! - [`host`] — host malware / posture / secrets detection orchestration
//! - [`posture`] — sshd_config / shadow / SUID misconfigurations
//! - [`secrets`] — credential-leak findings (privacy-safe evidence only)
//! - [`ioc`] — ThreatFeed load / match / enrich for TraceEvent
//! - [`network`] — network IOC/IDS detection over collected TraceEvents
//! - [`malware`] — re-export of [`agent_detect_malware`]
//!
//! Reusable Collect sources do not call this crate. Composition layers (the
//! standalone capability CLIs and `agentd`) pass collected facts into these
//! detectors, then hand normalized [`Detection`] values to Respond.
//!
//! CVE matching stays in the Python analyzer.

pub mod host;
pub mod ioc;
pub mod network;
pub mod posture;
pub mod secrets;

pub use agent_contract::Detection;
pub use agent_detect_malware as malware;
