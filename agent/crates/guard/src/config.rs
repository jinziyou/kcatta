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
    /// Paths to watch recursively (one inotify watch per existing subdir).
    pub paths: Vec<PathBuf>,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: ["/etc", "/usr/bin", "/usr/sbin", "/boot"]
                .iter()
                .map(PathBuf::from)
                .collect(),
        }
    }
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
            enabled: true,
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
    /// Local IOC feed JSON (reuses agent-flow's `ThreatFeed`); built-in demo feed when unset.
    pub intel: Option<PathBuf>,
    /// Per-iteration capture window in seconds.
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
    /// Directory flagged files are moved into (created on first use).
    pub vault_dir: PathBuf,
}

impl Default for ResponsePolicy {
    fn default() -> Self {
        Self {
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
            allowlist_paths: vec![PathBuf::from("/var/lib/posture-guard/quarantine")],
            allowlist_pids: vec![1],
            vault_dir: PathBuf::from("/var/lib/posture-guard/quarantine"),
        }
    }
}

/// Where events are reported.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ReportConfig {
    /// fusion base URL for `/ingest/guard-event` upload (off when unset).
    pub upload: Option<String>,
    /// Local NDJSON audit log path (one batch per line); off when unset.
    pub audit_log: Option<PathBuf>,
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
            upload: None,
            audit_log: Some(PathBuf::from("/var/log/posture/guard-audit.ndjson")),
            stdout: false,
            batch_max: 50,
            flush_secs: 5,
        }
    }
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
