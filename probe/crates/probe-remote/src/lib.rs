//! SSH agent-mode remote scanning for cyber-posture.
//!
//! Ships a static [`probe-asset`](probe_asset) binary to a target over SSH,
//! runs it against the live filesystem, pulls per-asset JSON back, and removes
//! all traces. Requires only SSH access and a writable directory on the target.
//!
//! # Pipeline
//!
//! 1. [`bootstrap::ensure_key_auth`] — password → key on first run
//! 2. [`ssh::SshSession`] — multiplexed OpenSSH control connection
//! 3. [`agent::run_agent_scan`] — upload, exec, pull, cleanup (RAII)
//! 4. [`report::finalize_asset_report`] — merge pulled JSON into [`probe_contract::AssetReport`]
//!
//! # Example
//!
//! ```no_run
//! use std::path::PathBuf;
//! use probe_asset::ScanTarget;
//! use probe_remote::{run_agent_scan, ssh::SshOptions, AgentScanOptions};
//!
//! let report = run_agent_scan(AgentScanOptions {
//!     ssh: SshOptions::new("root@10.0.0.1"),
//!     password: None,
//!     asset_binary: PathBuf::from("target/x86_64-unknown-linux-musl/release/probe-asset"),
//!     scan_root: "/".into(),
//!     target: ScanTarget::Host,
//!     output_dir: PathBuf::from("./reports/host"),
//!     task_id: None,
//!     malware: None,
//! })?;
//! for path in &report.files {
//!     println!("{}", path.display());
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! CLI usage and compatibility notes: [crate README](../README.md).

pub mod agent;
pub mod bootstrap;
pub mod report;
pub mod ssh;

pub use agent::{run_agent_scan, AgentScanOptions, AgentScanReport, MalwareAgentOptions};
pub use report::{
    assemble_asset_report, attach_malware, finalize_asset_report, write_asset_report,
};

use uuid::Uuid;

pub(crate) fn short_id(uuid: Uuid) -> String {
    uuid.simple().to_string()[..8].to_string()
}

/// Minimal POSIX single-quote escaping for values interpolated into remote
/// shell commands: wrap in single quotes and escape embedded quotes as `'\''`.
pub(crate) fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_is_eight_hex_chars() {
        let id = short_id(Uuid::nil());
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sh_quote_escapes_quotes() {
        assert_eq!(sh_quote("/tmp/x"), "'/tmp/x'");
        assert_eq!(sh_quote("a'b"), r#"'a'\''b'"#);
        assert_eq!(sh_quote(""), "''");
    }
}
