//! Remote agent-mode scanning.
//!
//! Ships a static `scanner-asset` binary to a target over SSH, runs it in
//! place against the live filesystem, pulls the per-asset JSON back, and
//! removes all traces. Only needs SSH access and a writable directory on the
//! target — no snapshot, NBD, or kernel module.
//!
//! - [`bootstrap`]: password → key auth (give a password once; subsequent
//!   runs are key-only).
//! - [`ssh`]: multiplexed OpenSSH session (`exec`, `scp_upload`/`scp_download`).
//! - [`agent::run_agent_scan`]: the end-to-end pipeline.

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
