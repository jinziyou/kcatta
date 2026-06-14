//! agentd orchestration (`agentd run`).
//!
//! A long-running scheduler that drives the collect-only capabilities on an
//! interval and (optionally) supervises guard, uploading everything to analyzer:
//!   * every `interval_secs`: a host static scan → `AssetReport` and a trace
//!     capture → `TraceBatch`, each POSTed to analyzer;
//!   * if `guard.enabled`: guard runs in a background thread, streaming
//!     `GuardEventBatch` to analyzer in real time (the same injected sink the
//!     `agentd guard --upload` path uses).
//!
//! Each stage (host / trace / guard) is gated independently by the JSON config
//! ([`RunConfig`]). A failing cycle is logged and retried next tick — one bad
//! upload never tears the daemon down.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use serde::Deserialize;

use crate::{ingest, AnalyzerGuardSink};

/// Orchestration config (`agentd run --config <path>`, JSON).
#[derive(Debug, Deserialize)]
pub struct RunConfig {
    /// analyzer base URL that every upload targets.
    pub upload_url: String,
    /// Seconds between host + trace collection cycles.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Host static-scan stage.
    #[serde(default)]
    pub host: HostStage,
    /// Network/file/process trace stage.
    #[serde(default)]
    pub trace: TraceStage,
    /// Real-time protection stage (off by default).
    #[serde(default)]
    pub guard: GuardStage,
}

fn default_interval() -> u64 {
    300
}
fn default_true() -> bool {
    true
}

/// Host static-scan stage config.
#[derive(Debug, Deserialize)]
pub struct HostStage {
    /// Run the host scan each cycle.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Filesystem root to scan (mounted image or `/`).
    #[serde(default = "default_root")]
    pub root: String,
    /// Also run the built-in malware signature scan.
    #[serde(default)]
    pub malware: bool,
}

fn default_root() -> String {
    "/".to_string()
}

impl Default for HostStage {
    fn default() -> Self {
        Self {
            enabled: true,
            root: default_root(),
            malware: false,
        }
    }
}

/// Trace stage config.
#[derive(Debug, Deserialize)]
pub struct TraceStage {
    /// Run a trace capture each cycle.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for TraceStage {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Guard (real-time protection) stage config.
#[derive(Debug, Deserialize)]
pub struct GuardStage {
    /// Supervise guard in the background (streams GuardEventBatch to analyzer).
    #[serde(default)]
    pub enabled: bool,
    /// Path to the guard JSON config.
    #[serde(default = "default_guard_config")]
    pub config_path: String,
}

fn default_guard_config() -> String {
    "/etc/kcatta/guard.json".to_string()
}

impl Default for GuardStage {
    fn default() -> Self {
        Self {
            enabled: false,
            config_path: default_guard_config(),
        }
    }
}

impl RunConfig {
    /// Read and parse a [`RunConfig`] from a JSON file.
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read run config {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parse run config {}", path.display()))
    }
}

/// Run the orchestration loop until SIGINT/SIGTERM.
pub fn orchestrate(config: RunConfig) -> anyhow::Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag = shutdown.clone();
        ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
            .context("install shutdown handler")?;
    }

    // Optional guard: stream protection events to analyzer from a background
    // thread. It supervises until the process exits (its own shutdown handling
    // stops the sensors); we detach it here.
    if config.guard.enabled {
        let url = config.upload_url.clone();
        let path = config.guard.config_path.clone();
        std::thread::Builder::new()
            .name("agentd-guard".into())
            .spawn(move || {
                if let Err(e) = run_guard(&path, &url) {
                    eprintln!("agentd: guard supervisor exited: {e:#}");
                }
            })
            .context("spawn guard supervisor thread")?;
    }

    eprintln!(
        "agentd: orchestrating every {}s (host={}, trace={}, guard={}) → {}",
        config.interval_secs,
        config.host.enabled,
        config.trace.enabled,
        config.guard.enabled,
        config.upload_url,
    );

    while !shutdown.load(Ordering::SeqCst) {
        if config.host.enabled {
            if let Err(e) = collect_host(&config) {
                eprintln!("agentd: host cycle failed: {e:#}");
            }
        }
        if config.trace.enabled {
            if let Err(e) = collect_trace(&config) {
                eprintln!("agentd: trace cycle failed: {e:#}");
            }
        }
        sleep_interruptible(config.interval_secs, &shutdown);
    }

    eprintln!("agentd: shutdown requested; exiting");
    Ok(())
}

/// One host scan → upload.
fn collect_host(config: &RunConfig) -> anyhow::Result<()> {
    let mut collectors = agent_host::default_collectors();
    if config.host.malware {
        collectors.push(Box::new(agent_host::MalwareCollector::default()));
    }
    let report = agent_host::run_scan_at(&collectors, &config.host.root).context("host scan")?;
    ingest::upload_report(&report, &config.upload_url)?;
    eprintln!(
        "agentd: uploaded AssetReport ({} assets, {} findings)",
        report.assets.len(),
        report.vulnerabilities.len()
    );
    Ok(())
}

/// One trace capture → upload.
fn collect_trace(config: &RunConfig) -> anyhow::Result<()> {
    let feed = agent_trace::ThreatFeed::builtin();
    let batch = agent_trace::run_capture_with_config(&feed, &agent_trace::CaptureConfig::default())
        .context("trace capture")?;
    ingest::upload_batch(&batch, &config.upload_url)?;
    eprintln!(
        "agentd: uploaded TraceBatch ({} network events)",
        batch.events.len()
    );
    Ok(())
}

/// Supervise guard with an analyzer-upload sink (blocks until guard stops).
fn run_guard(config_path: &str, upload_url: &str) -> anyhow::Result<()> {
    let gconfig = agent_guard::GuardConfig::load(Path::new(config_path))
        .with_context(|| format!("load guard config {config_path}"))?;
    let sink: Box<dyn agent_guard::ReportSink> =
        Box::new(AnalyzerGuardSink::new(upload_url.to_string()));
    agent_guard::Supervisor::new(gconfig, vec![sink]).run()
}

/// Sleep `secs`, waking early if shutdown is signalled.
fn sleep_interruptible(secs: u64, shutdown: &Arc<AtomicBool>) {
    for _ in 0..secs {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let cfg: RunConfig = serde_json::from_str(
            r#"{
                "upload_url": "http://analyzer:8000",
                "interval_secs": 60,
                "host": { "enabled": true, "root": "/mnt/img", "malware": true },
                "trace": { "enabled": false },
                "guard": { "enabled": true, "config_path": "/etc/kcatta/guard.json" }
            }"#,
        )
        .expect("parse");
        assert_eq!(cfg.interval_secs, 60);
        assert!(cfg.host.malware);
        assert_eq!(cfg.host.root, "/mnt/img");
        assert!(!cfg.trace.enabled);
        assert!(cfg.guard.enabled);
    }

    #[test]
    fn applies_defaults() {
        // Only the required field; everything else defaults.
        let cfg: RunConfig =
            serde_json::from_str(r#"{ "upload_url": "http://a:8000" }"#).expect("parse");
        assert_eq!(cfg.interval_secs, 300);
        assert!(cfg.host.enabled && cfg.host.root == "/" && !cfg.host.malware);
        assert!(cfg.trace.enabled);
        assert!(!cfg.guard.enabled);
        assert_eq!(cfg.guard.config_path, "/etc/kcatta/guard.json");
    }
}
