//! agentd orchestration (`agentd run`).
//!
//! A long-running scheduler that drives the collect-only capabilities on an
//! interval and (optionally) supervises guard, uploading everything to Form:
//!   * every `interval_secs`: a host static scan → `AssetReport` and a trace
//!     capture → `TraceBatch`, each POSTed to Form;
//!   * if `guard.enabled`: guard runs in a background thread, streaming
//!     `GuardEventBatch` to Form in real time (the same injected sink the
//!     `agentd respond --upload` path uses).
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

use crate::{ingest, FormGuardSink};

/// Orchestration config (`agentd run --config <path>`, JSON).
#[derive(Debug, Deserialize)]
pub struct RunConfig {
    /// Form base URL that every upload targets.
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
    /// Run host security-posture checks (sshd_config / shadow / SUID misconfig).
    /// On by default; set false to opt out.
    #[serde(default = "default_true")]
    pub posture: bool,
    /// Scan for leaked secrets (private keys, cloud/provider tokens). Opt-in
    /// (walks + reads small files); off by default.
    #[serde(default)]
    pub secrets: bool,
    /// Collect packages/services from container rootfs snapshots and packages
    /// from local images. On by default to match `collect-host -t all`.
    #[serde(default = "default_true")]
    pub container_assets: bool,
    /// Maximum container rootfs snapshots inspected per cycle.
    #[serde(default = "default_max_containers")]
    pub max_containers: usize,
    /// Include stopped containers whose rootfs is still present.
    #[serde(default = "default_true")]
    pub include_stopped_containers: bool,
    /// Include packages from locally stored container images.
    #[serde(default = "default_true")]
    pub container_images: bool,
    /// Maximum local images assembled and inspected per cycle.
    #[serde(default = "default_max_images")]
    pub max_images: usize,
}

fn default_root() -> String {
    "/".to_string()
}

fn default_max_containers() -> usize {
    64
}

fn default_max_images() -> usize {
    32
}

impl Default for HostStage {
    fn default() -> Self {
        Self {
            enabled: true,
            root: default_root(),
            malware: false,
            posture: true,
            secrets: false,
            container_assets: true,
            max_containers: default_max_containers(),
            include_stopped_containers: true,
            container_images: true,
            max_images: default_max_images(),
        }
    }
}

/// Trace capture backend for the orchestrated trace stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceBackend {
    /// Synthetic events — NO real traffic. Requires no privileges; useful for
    /// smoke tests / demos only. It must be selected explicitly and is flagged
    /// loudly at startup to avoid synthetic events entering production by accident.
    Mock,
    /// Live libpcap capture (needs the `pcap` build feature + capture privileges).
    /// Userspace L7 parsing yields JA3 / TLS SNI / DNS.
    Pcap,
    /// In-kernel eBPF cgroup-skb flow telemetry (needs the `ebpf` build feature +
    /// CAP_BPF + cgroup-v2). L4-only (no JA3/SNI/DNS); an unavailable backend
    /// falls back only to compiled live pcap, otherwise the cycle fails.
    Ebpf,
    /// OS connection-table polling (needs the `winnet` build feature): IP Helper
    /// on Windows / `/proc` on Linux. The Windows network backend — no admin /
    /// libpcap / eBPF; 5-tuple TCP connections only (no byte counters).
    #[serde(rename = "winnet")]
    #[default]
    WinNet,
}

/// Trace stage config.
#[derive(Debug, Deserialize)]
pub struct TraceStage {
    /// Run a trace capture each cycle.
    #[serde(default)]
    pub enabled: bool,
    /// Capture backend (`winnet` default; `mock` is explicit development-only).
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
    /// Optional local IOC feed. When absent, the orchestration path stays
    /// collect-only; it never substitutes the built-in demo indicators.
    #[serde(default)]
    pub intel: Option<String>,
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
            // Safe production default: no trace is uploaded until the operator
            // explicitly enables a real capture stage. If enabled without a
            // backend, WinNet is real connection-table telemetry.
            enabled: false,
            backend: TraceBackend::WinNet,
            iface: default_iface(),
            duration_secs: default_capture_secs(),
            bpf: default_bpf(),
            intel: None,
        }
    }
}

/// Guard (real-time protection) stage config.
#[derive(Debug, Deserialize)]
pub struct GuardStage {
    /// Supervise guard in the background (streams GuardEventBatch to Form).
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
        let config: Self = serde_json::from_str(&text)
            .with_context(|| format!("parse run config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.interval_secs > 0,
            "interval_secs must be greater than zero"
        );
        let url = reqwest::Url::parse(&self.upload_url)
            .with_context(|| format!("invalid upload_url {}", self.upload_url))?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "upload_url must be an absolute http(s) URL with a host"
        );
        if self.host.container_assets {
            anyhow::ensure!(
                self.host.max_containers > 0,
                "host.max_containers must be greater than zero"
            );
            if self.host.container_images {
                anyhow::ensure!(
                    self.host.max_images > 0,
                    "host.max_images must be greater than zero"
                );
            }
        }
        Ok(())
    }
}

/// Run the orchestration loop until SIGINT/SIGTERM.
pub fn orchestrate(config: RunConfig) -> anyhow::Result<()> {
    config.validate()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag = shutdown.clone();
        ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
            .context("install shutdown handler")?;
    }

    // Optional Respond stage. It shares the same shutdown token as the periodic
    // Collect/Detect stages, so one signal drains the whole SOC loop.
    let guard_handle = if config.guard.enabled {
        let url = config.upload_url.clone();
        let path = config.guard.config_path.clone();
        let guard_shutdown = Arc::clone(&shutdown);
        Some(
            std::thread::Builder::new()
                .name("agentd-respond".into())
                .spawn(move || {
                    let result = run_guard(&path, &url, Arc::clone(&guard_shutdown));
                    if result.is_err() {
                        // Wake the periodic loop promptly; otherwise it might
                        // sleep until the next long collection interval before
                        // noticing that endpoint protection has stopped.
                        guard_shutdown.store(true, Ordering::SeqCst);
                    }
                    result
                })
                .context("spawn respond supervisor thread")?,
        )
    } else {
        None
    };

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
             not real captured traffic. For live capture set trace.backend to \"pcap\"/\"ebpf\" \
             (Linux, --features pcap/ebpf) or \"winnet\" (Windows/Linux connection table, \
             --features winnet)."
        );
    }

    while !shutdown.load(Ordering::SeqCst) {
        if guard_handle
            .as_ref()
            .is_some_and(|handle| handle.is_finished())
        {
            eprintln!("agentd: respond stage exited unexpectedly; stopping the SOC loop");
            shutdown.store(true, Ordering::SeqCst);
            break;
        }
        if config.host.enabled {
            if let Err(e) = collect_host(&config) {
                eprintln!("agentd: host cycle failed: {e:#}");
            }
        }
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        if config.trace.enabled {
            if let Err(e) = collect_trace(&config) {
                eprintln!("agentd: trace cycle failed: {e:#}");
            }
        }
        sleep_interruptible(config.interval_secs, &shutdown);
    }

    // Stop and drain Respond before flushing transport state, ensuring its final
    // GuardEventBatch can enter the upload/spool path before process exit.
    shutdown.store(true, Ordering::SeqCst);
    let guard_result = guard_handle.map(|handle| match handle.join() {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("respond supervisor thread panicked")),
    });

    // Graceful shutdown: try to push any spooled backlog now rather than leaving
    // it queued until a next cycle that will never come.
    eprintln!("agentd: shutdown requested; attempting one bounded spool delivery");
    let flushed = ingest::flush_spool_bounded(&config.upload_url, 1);
    eprintln!(
        "agentd: shutdown: delivered {flushed} spooled upload(s); remaining items stay durable"
    );
    if let Some(result) = guard_result {
        result.context("respond stage")?;
    }
    Ok(())
}

/// One host scan → upload (asset collect, then detect phase).
fn collect_host(config: &RunConfig) -> anyhow::Result<()> {
    let sources: Vec<Box<dyn agent_collect_host::Source>> = vec![Box::new(
        agent_collect_host::FilesystemSource::new(host_container_scan(&config.host)),
    )];
    let detect = agent_detect::host::DetectOptions {
        malware: config
            .host
            .malware
            .then(agent_detect::host::MalwareDetectOptions::default),
        posture: config.host.posture,
        secrets: config.host.secrets,
    };
    let mut report = agent_collect_host::run_scan_at_with_opts(
        &sources,
        &config.host.root,
        Vec::new(),
        agent_collect_host::WindowsPackageProfile::default(),
        true,
    )
    .context("host asset collection")?;
    let findings = agent_detect::host::detect(&config.host.root, &report.host.host_id, &detect)
        .context("host detection")?;
    report.detector_runs = Some(agent_detect::host::completed_runs(&detect, &findings));
    report.vulnerabilities.extend(findings);
    report.normalize_wire_fields()?;
    match ingest::upload_report(&report, &config.upload_url)? {
        ingest::UploadOutcome::Delivered => eprintln!(
            "agentd: uploaded AssetReport ({} assets, {} findings)",
            report.assets.len(),
            report.vulnerabilities.len()
        ),
        ingest::UploadOutcome::Spooled => eprintln!(
            "agentd: form unreachable; spooled AssetReport ({} assets) for later delivery",
            report.assets.len()
        ),
    }
    Ok(())
}

fn host_container_scan(stage: &HostStage) -> agent_collect_host::ContainerScanOptions {
    if !stage.container_assets {
        return agent_collect_host::ContainerScanOptions::default();
    }
    let mut options = agent_collect_host::ContainerScanOptions::enabled();
    options.max_containers = stage.max_containers;
    options.include_stopped = stage.include_stopped_containers;
    options.scan_images = stage.container_images;
    options.max_images = stage.max_images;
    options
}

/// One trace capture → optional IOC detect → upload.
fn collect_trace(config: &RunConfig) -> anyhow::Result<()> {
    let capture_config = build_capture_config(&config.trace)?;
    let mut batch = agent_collect_trace::capture_batch(&capture_config).context("trace capture")?;
    if let Some(path) = &config.trace.intel {
        let feed = agent_detect::ioc::ThreatFeed::from_json_path(path)
            .with_context(|| format!("load trace IOC feed {path}"))?;
        feed.enrich(&mut batch.events);
    }
    match ingest::upload_batch(&batch, &config.upload_url)? {
        ingest::UploadOutcome::Delivered => eprintln!(
            "agentd: uploaded TraceBatch ({} network events)",
            batch.events.len()
        ),
        ingest::UploadOutcome::Spooled => eprintln!(
            "agentd: form unreachable; spooled TraceBatch ({} network events) for later delivery",
            batch.events.len()
        ),
    }
    Ok(())
}

/// Build the capture config for the explicitly configured backend.
///
/// Live backends never degrade to synthetic mock events: missing build support
/// is a failed collection cycle, preserving the configured information source.
fn build_capture_config(stage: &TraceStage) -> anyhow::Result<agent_collect_trace::CaptureConfig> {
    match stage.backend {
        TraceBackend::Pcap => {
            #[cfg(feature = "pcap")]
            {
                Ok(agent_collect_trace::CaptureConfig::pcap(
                    stage.iface.clone(),
                    stage.duration_secs.max(1),
                    stage.bpf.clone(),
                ))
            }
            #[cfg(not(feature = "pcap"))]
            {
                anyhow::bail!(
                    "trace backend 'pcap' requested but this build lacks the pcap feature"
                )
            }
        }
        TraceBackend::Ebpf => {
            #[cfg(feature = "ebpf")]
            {
                // L4-only eBPF backend; iface/bpf parameterize its pcap fallback.
                Ok(agent_collect_trace::CaptureConfig::ebpf(
                    stage.iface.clone(),
                    stage.duration_secs.max(1),
                    stage.bpf.clone(),
                ))
            }
            #[cfg(not(feature = "ebpf"))]
            {
                anyhow::bail!(
                    "trace backend 'ebpf' requested but this build lacks the ebpf feature"
                )
            }
        }
        TraceBackend::WinNet => {
            #[cfg(feature = "winnet")]
            {
                Ok(agent_collect_trace::CaptureConfig::win_net(
                    stage.duration_secs.max(1),
                ))
            }
            #[cfg(not(feature = "winnet"))]
            {
                anyhow::bail!(
                    "trace backend 'winnet' requested but this build lacks the winnet feature"
                )
            }
        }
        TraceBackend::Mock => Ok(agent_collect_trace::CaptureConfig::default()),
    }
}

/// Supervise guard with a Form-upload sink (blocks until guard stops).
fn run_guard(config_path: &str, upload_url: &str, shutdown: Arc<AtomicBool>) -> anyhow::Result<()> {
    let gconfig = agent_respond::GuardConfig::load(Path::new(config_path))
        .with_context(|| format!("load guard config {config_path}"))?;
    let sink: Box<dyn agent_respond::ReportSink> =
        Box::new(FormGuardSink::new(upload_url.to_string()));
    agent_respond::Supervisor::new(gconfig, vec![sink]).run_with_shutdown(shutdown)
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
                "upload_url": "http://form:10067",
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
            serde_json::from_str(r#"{ "upload_url": "http://a:10068" }"#).expect("parse");
        assert_eq!(cfg.interval_secs, 300);
        assert!(cfg.host.enabled && cfg.host.root == "/" && !cfg.host.malware);
        assert!(cfg.host.container_assets);
        let container_scan = host_container_scan(&cfg.host);
        assert!(container_scan.enabled && container_scan.scan_images);
        assert_eq!(container_scan.max_containers, 64);
        assert_eq!(container_scan.max_images, 32);
        assert!(!cfg.trace.enabled);
        assert_eq!(cfg.trace.backend, TraceBackend::WinNet);
        assert!(cfg.trace.intel.is_none());
        assert!(!cfg.guard.enabled);
        assert_eq!(cfg.guard.config_path, "/etc/kcatta/guard.json");
    }

    #[test]
    fn parses_pcap_trace_backend() {
        let cfg: RunConfig = serde_json::from_str(
            r#"{
                "upload_url": "http://a:10068",
                "trace": { "enabled": true, "backend": "pcap", "iface": "eth0", "duration_secs": 30, "bpf": "tcp port 443" }
            }"#,
        )
        .expect("parse");
        assert_eq!(cfg.trace.backend, TraceBackend::Pcap);
        assert_eq!(cfg.trace.iface, "eth0");
        assert_eq!(cfg.trace.duration_secs, 30);
        assert_eq!(cfg.trace.bpf, "tcp port 443");
    }

    #[test]
    fn parses_winnet_trace_backend() {
        // The Windows network backend, selected from the orchestration config.
        let cfg: RunConfig = serde_json::from_str(
            r#"{
                "upload_url": "http://a:10068",
                "trace": {
                    "enabled": true,
                    "backend": "winnet",
                    "duration_secs": 15,
                    "intel": "/etc/kcatta/ioc.json"
                }
            }"#,
        )
        .expect("parse");
        assert_eq!(cfg.trace.backend, TraceBackend::WinNet);
        assert_eq!(cfg.trace.duration_secs, 15);
        assert_eq!(cfg.trace.intel.as_deref(), Some("/etc/kcatta/ioc.json"));
    }

    #[test]
    fn mock_backend_is_only_selected_explicitly() {
        let stage = TraceStage {
            enabled: true,
            backend: TraceBackend::Mock,
            ..TraceStage::default()
        };
        let config = build_capture_config(&stage).expect("explicit mock backend");
        assert!(matches!(
            config.backend,
            agent_collect_trace::CaptureBackend::Mock
        ));
    }

    #[test]
    fn enabling_trace_without_backend_never_selects_mock() {
        let cfg: RunConfig = serde_json::from_str(
            r#"{
                "upload_url": "http://a:10068",
                "trace": { "enabled": true }
            }"#,
        )
        .expect("parse");

        assert!(cfg.trace.enabled);
        assert_eq!(cfg.trace.backend, TraceBackend::WinNet);
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn missing_live_backend_feature_is_an_error_not_mock() {
        let stage = TraceStage {
            backend: TraceBackend::Pcap,
            ..TraceStage::default()
        };
        let error = build_capture_config(&stage).expect_err("pcap feature is absent");
        assert!(error.to_string().contains("lacks the pcap feature"));
    }

    #[test]
    fn rejects_zero_interval_and_non_http_upload_urls() {
        let mut config: RunConfig =
            serde_json::from_str(r#"{ "upload_url": "http://form:10067" }"#).unwrap();
        config.interval_secs = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("greater than zero"));

        config.interval_secs = 1;
        config.upload_url = "file:///tmp/form".into();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("absolute http(s)"));
    }

    #[test]
    fn host_container_inventory_can_be_bounded_or_explicitly_disabled() {
        let cfg: RunConfig = serde_json::from_str(
            r#"{
                "upload_url": "http://form:10067",
                "host": {
                    "container_assets": true,
                    "max_containers": 7,
                    "include_stopped_containers": false,
                    "container_images": true,
                    "max_images": 3
                }
            }"#,
        )
        .unwrap();
        let options = host_container_scan(&cfg.host);
        assert!(options.enabled && options.scan_packages && options.scan_services);
        assert!(!options.include_stopped);
        assert!(options.scan_images);
        assert_eq!(options.max_containers, 7);
        assert_eq!(options.max_images, 3);

        let disabled: RunConfig = serde_json::from_str(
            r#"{
                "upload_url": "http://form:10067",
                "host": { "container_assets": false }
            }"#,
        )
        .unwrap();
        assert!(!host_container_scan(&disabled.host).enabled);
    }
}
