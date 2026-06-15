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

/// Trace capture backend for the orchestrated trace stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceBackend {
    /// Synthetic events — NO real traffic. Requires no privileges; useful for
    /// smoke tests / demos only. This is the default, so it is flagged loudly at
    /// startup to avoid operators mistaking synthetic data for real monitoring.
    #[default]
    Mock,
    /// Live libpcap capture (needs the `pcap` build feature + capture privileges).
    /// Userspace L7 parsing yields JA3 / TLS SNI / DNS.
    Pcap,
    /// In-kernel eBPF cgroup-skb flow telemetry (needs the `ebpf` build feature +
    /// CAP_BPF + cgroup-v2). L4-only (no JA3/SNI/DNS); falls back to pcap/mock at
    /// runtime when unavailable. Recommended lightweight network backend.
    Ebpf,
}

/// Trace stage config.
#[derive(Debug, Deserialize)]
pub struct TraceStage {
    /// Run a trace capture each cycle.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Capture backend (`mock` default, or `pcap` for live capture).
    #[serde(default)]
    pub backend: TraceBackend,
    /// Capture interface for the pcap backend (`any`, `eth0`, …).
    #[serde(default = "default_iface")]
    #[cfg_attr(not(feature = "pcap"), allow(dead_code))]
    pub iface: String,
    /// Per-cycle capture window in seconds (pcap backend).
    #[serde(default = "default_capture_secs")]
    #[cfg_attr(not(feature = "pcap"), allow(dead_code))]
    pub duration_secs: u64,
    /// BPF filter for the pcap backend.
    #[serde(default = "default_bpf")]
    #[cfg_attr(not(feature = "pcap"), allow(dead_code))]
    pub bpf: String,
}

fn default_iface() -> String {
    "any".to_string()
}
fn default_capture_secs() -> u64 {
    10
}
fn default_bpf() -> String {
    "tcp or udp or icmp".to_string()
}

impl Default for TraceStage {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: TraceBackend::Mock,
            iface: default_iface(),
            duration_secs: default_capture_secs(),
            bpf: default_bpf(),
        }
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
    if config.trace.enabled && config.trace.backend == TraceBackend::Mock {
        eprintln!(
            "agentd: WARNING trace backend is MOCK — uploaded TraceBatch events are SYNTHETIC, \
             not real captured traffic. Set trace.backend=\"pcap\" (built with --features pcap) \
             for live capture."
        );
    }

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
    let capture_config = build_capture_config(&config.trace);
    let batch =
        agent_trace::run_capture_with_config(&feed, &capture_config).context("trace capture")?;
    ingest::upload_batch(&batch, &config.upload_url)?;
    eprintln!(
        "agentd: uploaded TraceBatch ({} network events)",
        batch.events.len()
    );
    Ok(())
}

/// Build the capture config for the configured backend. A `pcap` request on a
/// build without the `pcap` feature falls back to mock with a clear warning
/// rather than silently producing synthetic data labelled as live capture.
fn build_capture_config(stage: &TraceStage) -> agent_trace::CaptureConfig {
    match stage.backend {
        TraceBackend::Pcap => {
            #[cfg(feature = "pcap")]
            {
                agent_trace::CaptureConfig::pcap(
                    stage.iface.clone(),
                    stage.duration_secs.max(1),
                    stage.bpf.clone(),
                )
            }
            #[cfg(not(feature = "pcap"))]
            {
                eprintln!(
                    "agentd: trace backend 'pcap' requested but this build lacks the pcap \
                     feature; falling back to MOCK (synthetic) traffic"
                );
                agent_trace::CaptureConfig::default()
            }
        }
        TraceBackend::Ebpf => {
            #[cfg(feature = "ebpf")]
            {
                // L4-only eBPF backend; iface/bpf parameterize its pcap fallback.
                agent_trace::CaptureConfig::ebpf(
                    stage.iface.clone(),
                    stage.duration_secs.max(1),
                    stage.bpf.clone(),
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                eprintln!(
                    "agentd: trace backend 'ebpf' requested but this build lacks the ebpf \
                     feature; falling back to MOCK (synthetic) traffic"
                );
                agent_trace::CaptureConfig::default()
            }
        }
        TraceBackend::Mock => agent_trace::CaptureConfig::default(),
    }
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
        // Default trace backend is mock (synthetic) and flagged at startup.
        assert_eq!(cfg.trace.backend, TraceBackend::Mock);
        assert!(!cfg.guard.enabled);
        assert_eq!(cfg.guard.config_path, "/etc/kcatta/guard.json");
    }

    #[test]
    fn parses_pcap_trace_backend() {
        let cfg: RunConfig = serde_json::from_str(
            r#"{
                "upload_url": "http://a:8000",
                "trace": { "enabled": true, "backend": "pcap", "iface": "eth0", "duration_secs": 30, "bpf": "tcp port 443" }
            }"#,
        )
        .expect("parse");
        assert_eq!(cfg.trace.backend, TraceBackend::Pcap);
        assert_eq!(cfg.trace.iface, "eth0");
        assert_eq!(cfg.trace.duration_secs, 30);
        assert_eq!(cfg.trace.bpf, "tcp port 443");
    }
}
