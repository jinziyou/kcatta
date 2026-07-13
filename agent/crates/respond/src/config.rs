//! Guard daemon configuration (JSON), loaded once at startup.
//!
//! Safe by default: [`Mode::Monitor`] and every active-response gate is `false`,
//! so an out-of-the-box guard observes and reports but performs **no** destructive
//! action until enforcement is deliberately enabled (mode + per-action gate).

use std::path::PathBuf;

use agent_contract::Severity;
use serde::Deserialize;

/// Whether the guard only observes (`monitor`) or may take active response
/// (`enforce`). Active response additionally requires the matching per-action
/// gate in [`ResponsePolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Detect and report only (default). No active response.
    #[default]
    Monitor,
    /// Active response permitted, subject to per-action gates and safety vetoes.
    Enforce,
}

/// File-integrity monitoring sensor config.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FimConfig {
    /// Enable the FIM sensor.
    pub enabled: bool,
    /// Directories to watch (one inotify watch per configured path; non-recursive in v1).
    pub paths: Vec<PathBuf>,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: cfg!(feature = "fim") && cfg!(any(target_os = "linux", target_os = "windows")),
            paths: default_fim_paths(),
        }
    }
}

#[cfg(target_os = "windows")]
fn default_fim_paths() -> Vec<PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    [
        root.join(r"System32\config"),
        root.join(r"System32\drivers\etc"),
        root.join(r"System32\Tasks"),
    ]
    .into_iter()
    .collect()
}

#[cfg(not(target_os = "windows"))]
fn default_fim_paths() -> Vec<PathBuf> {
    ["/etc", "/usr/bin", "/usr/sbin", "/boot"]
        .into_iter()
        .map(PathBuf::from)
        .collect()
}

/// Process / behavior monitoring sensor config.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BehaviorConfig {
    /// Enable the behavior sensor.
    pub enabled: bool,
    /// `/proc` poll interval in milliseconds.
    pub poll_interval_ms: u64,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            // The current process-rule collector reads Linux `/proc`. On other
            // platforms or feature-trimmed builds, do not silently enable a
            // sensor that cannot be built.
            enabled: cfg!(all(feature = "behavior", target_os = "linux")),
            poll_interval_ms: 1000,
        }
    }
}

/// On-access malware scan sensor config (needs `CAP_SYS_ADMIN`; off by default).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OnAccessConfig {
    /// Enable the on-access sensor (requires the `onaccess` build feature).
    pub enabled: bool,
    /// Extra malware signatures (JSON) loaded on top of the built-in set.
    pub signatures: Option<PathBuf>,
    /// Mount points / directories to mark for open-permission events.
    pub paths: Vec<PathBuf>,
}

/// Network linkage / IDS sensor config.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Enable the network sensor (requires the `network` build feature).
    pub enabled: bool,
    /// Capture interface (`any`, `eth0`, …); used only with the `pcap` feature.
    pub iface: String,
    /// Local IOC feed JSON. A configured feed must load successfully. When
    /// unset, only an `ids` build may run (with an empty IOC feed); an IOC-only
    /// network sensor treats the missing feed as a fatal configuration error.
    pub intel: Option<PathBuf>,
    /// Requested capture window in seconds. The real-time sensor bounds each
    /// blocking slice to five seconds so shutdown remains responsive.
    pub window_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            iface: "any".to_string(),
            intel: None,
            window_secs: 2,
        }
    }
}

/// Active-response policy. Every gate defaults `false`; an action fires only when
/// [`Mode::Enforce`] **and** its gate is on **and** severity ≥ [`Self::severity_threshold`]
/// **and** the safety layer does not veto it.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ResponsePolicy {
    /// Allow denying a malware-triggering file open in the fanotify permission
    /// hook. This is independent from quarantine and defaults off: merely
    /// selecting enforce mode must never turn a sensor into an implicit blocker.
    pub allow_block_open: bool,
    /// Allow moving flagged files into the quarantine vault (never deletes).
    pub allow_quarantine: bool,
    /// Allow inserting firewall drop rules for IOC/IDS destinations.
    pub allow_netblock: bool,
    /// Allow killing flagged processes (scaffolded; not part of the v1 enforce set).
    pub allow_kill: bool,
    /// Minimum severity for any active response.
    pub severity_threshold: Severity,
    /// Path prefixes that must never be acted on (self-DoS guard).
    pub critical_paths: Vec<PathBuf>,
    /// Extra paths the responder must never touch (e.g. the vault itself).
    pub allowlist_paths: Vec<PathBuf>,
    /// PIDs that must never be killed (always includes PID 1 and the guard's own PID).
    pub allowlist_pids: Vec<u32>,
    /// Process `comm` names — in addition to the built-in critical set — the
    /// responder must never kill. Extend this with your own critical services
    /// (e.g. `"nginx"`, `"postgres"`, `"redis-server"`) so an `exe_deleted_running`
    /// false positive after a package upgrade can never SIGKILL them. The built-in
    /// set (systemd / sshd / dbus / container runtimes / databases / web servers)
    /// is always protected regardless of this list — it can only add, never remove.
    pub protected_processes: Vec<String>,
    /// Directory flagged files are moved into (created on first use).
    pub vault_dir: PathBuf,
    /// Destination IPs the responder must never block, beyond the automatic
    /// loopback/private/gateway/DNS vetoes (e.g. the analyzer upload address).
    pub never_block_ips: Vec<String>,
    /// Allow blocking RFC1918 / unique-local private destinations. Off by default:
    /// an IOC-triggered block of a private address is far more likely to sever the
    /// host from its own network than to stop an attacker, so intra-LAN blocking
    /// must be opted into deliberately. Loopback/gateway/DNS stay vetoed regardless.
    pub allow_block_private: bool,
}

impl Default for ResponsePolicy {
    fn default() -> Self {
        Self {
            allow_block_open: false,
            allow_quarantine: false,
            allow_netblock: false,
            allow_kill: false,
            severity_threshold: Severity::High,
            // NOT "/" — that would `starts_with`-match every absolute path and
            // make quarantine impossible. System binaries/libs are covered by the
            // system-prefix guard in `safety`; these are explicit extras.
            critical_paths: [
                "/bin",
                "/sbin",
                "/usr",
                "/lib",
                "/lib64",
                "/boot",
                "/etc/passwd",
                "/etc/shadow",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            allowlist_paths: vec![PathBuf::from("/var/lib/agent-respond/quarantine")],
            allowlist_pids: vec![1],
            // Empty by default: the built-in critical set in `safety` already
            // covers the common self-DoS targets; this is for site-specific extras.
            protected_processes: Vec::new(),
            vault_dir: PathBuf::from("/var/lib/agent-respond/quarantine"),
            never_block_ips: Vec::new(),
            allow_block_private: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_json_without_block_open_gate_remains_safe_and_loadable() {
        let config: GuardConfig = serde_json::from_str(
            r#"{
                "mode": "enforce",
                "onaccess": { "enabled": true, "paths": ["/opt"] },
                "response": { "allow_quarantine": true }
            }"#,
        )
        .expect("legacy guard config must remain compatible");

        assert_eq!(config.mode, Mode::Enforce);
        assert!(config.response.allow_quarantine);
        assert!(!config.response.allow_block_open);
    }
}

/// Where events are reported.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ReportConfig {
    /// Local NDJSON audit log path (one batch per line); off when unset.
    pub audit_log: Option<PathBuf>,
    /// Hard byte cap for the local audit log; reaching it resets the file in
    /// place and retains the newest complete batch instead of filling the disk.
    pub audit_max_bytes: u64,
    /// Also print each flushed batch to stdout (dev).
    pub stdout: bool,
    /// Flush a batch once it reaches this many events.
    pub batch_max: usize,
    /// Flush a partial batch at least this often (seconds).
    pub flush_secs: u64,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            audit_log: Some(default_audit_log()),
            audit_max_bytes: 64 * 1024 * 1024,
            stdout: false,
            batch_max: 50,
            flush_secs: 5,
        }
    }
}

#[cfg(target_os = "windows")]
fn default_audit_log() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("kcatta")
        .join("guard-audit.ndjson")
}

#[cfg(not(target_os = "windows"))]
fn default_audit_log() -> PathBuf {
    PathBuf::from("/var/log/kcatta/guard-audit.ndjson")
}

/// Top-level guard configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GuardConfig {
    /// Monitor (default) vs enforce.
    pub mode: Mode,
    /// Host id; auto-resolved from the hostname when unset.
    pub host_id: Option<String>,
    /// FIM sensor.
    pub fim: FimConfig,
    /// Behavior sensor.
    pub behavior: BehaviorConfig,
    /// On-access scan sensor.
    pub onaccess: OnAccessConfig,
    /// Network / IDS sensor.
    pub network: NetworkConfig,
    /// Active-response policy.
    pub response: ResponsePolicy,
    /// Reporting sinks.
    pub report: ReportConfig,
}

impl GuardConfig {
    /// Load config from a JSON file. A missing path yields the safe defaults
    /// (monitor mode, no enforcement) so the daemon is runnable out of the box.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(serde_json::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!("read config {}: {e}", path.display())),
        }
    }
}
