//! `posture-flow` CLI: subcommands + run, shared by the standalone `posture-flow`
//! binary and the umbrella `agent flow` subcommand.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};

use crate::intel::sync::{self, feodo};
use crate::{run_capture_with_config, CaptureConfig, ThreatFeed};

/// Traffic-detection subcommands (`posture-flow <cmd>` / `agent flow <cmd>`).
#[derive(Debug, Subcommand)]
pub enum FlowCommand {
    /// Capture one cycle (mock | pcap) → IOC match → FlowBatch.
    Capture(FlowArgs),
    /// Download threat-intel IOC feeds into local JSON for `capture --intel`.
    IntelSync(IntelSyncArgs),
}

/// Dispatch a [`FlowCommand`].
pub fn run(command: FlowCommand) -> Result<()> {
    match command {
        FlowCommand::Capture(args) => run_capture_cmd(args),
        FlowCommand::IntelSync(args) => run_intel_sync(args),
    }
}

// ----------------------------------------------------------------- capture

/// `capture` arguments.
#[derive(Debug, Args)]
pub struct FlowArgs {
    /// Pretty-print the JSON output (default: compact).
    #[arg(long)]
    pretty: bool,

    /// Write JSON to a file instead of stdout.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Threat-intel IOC feed (JSON) to match flows against. Defaults to a small
    /// built-in demo feed when omitted.
    #[arg(long, value_name = "PATH")]
    intel: Option<PathBuf>,

    /// Upload the batch to fusion after capture (`<URL>/ingest/flow-batch`).
    #[arg(long, value_name = "URL")]
    upload: Option<String>,

    /// Use synthetic mock flows instead of live capture (default).
    #[arg(long, conflicts_with_all = ["pcap", "iface", "duration", "bpf"])]
    mock: bool,

    /// Capture live traffic via libpcap (requires the `pcap` feature at build).
    #[arg(long, conflicts_with = "mock")]
    pcap: bool,

    /// Network interface for pcap capture (`any`, `eth0`, `lo`, ...).
    #[arg(long, default_value = "any", requires = "pcap")]
    iface: String,

    /// Capture duration in seconds (pcap mode).
    #[arg(long, default_value_t = 5, requires = "pcap")]
    duration: u64,

    /// BPF filter expression (pcap mode).
    #[arg(long, default_value = "tcp or udp or icmp", requires = "pcap")]
    bpf: String,

    /// List libpcap capture devices and exit (requires the `pcap` feature).
    #[cfg(feature = "pcap")]
    #[arg(long)]
    list_devices: bool,
}

fn run_capture_cmd(args: FlowArgs) -> Result<()> {
    #[cfg(feature = "pcap")]
    if args.list_devices {
        for name in crate::pcap::list_devices().context("list pcap devices")? {
            println!("{name}");
        }
        return Ok(());
    }

    let feed = match &args.intel {
        Some(path) => ThreatFeed::from_json_path(path).context("loading threat-intel feed")?,
        None => ThreatFeed::builtin(),
    };

    let capture_config = build_capture_config(&args)?;
    let batch = run_capture_with_config(&feed, &capture_config).context("running capture")?;

    if let Some(base) = &args.upload {
        agent_ingest::upload_batch(&batch, base).context("uploading batch")?;
        let hits: usize = batch.flows.iter().map(|f| f.threat_intel.len()).sum();
        eprintln!(
            "uploaded {} ({} flow(s), {} threat-intel hit(s)) to {base}",
            batch.batch_id,
            batch.flows.len(),
            hits,
        );
    }

    agent_cli_common::output::write_json(&batch, args.out.as_deref(), args.pretty)
}

fn build_capture_config(args: &FlowArgs) -> Result<CaptureConfig> {
    if args.mock || !args.pcap {
        return Ok(CaptureConfig::mock());
    }

    #[cfg(feature = "pcap")]
    {
        Ok(CaptureConfig::pcap(
            args.iface.clone(),
            args.duration,
            args.bpf.clone(),
        ))
    }

    #[cfg(not(feature = "pcap"))]
    {
        let _ = args;
        bail!("rebuild with `--features pcap` to use live capture (--pcap)")
    }
}

// --------------------------------------------------------------- intel-sync

/// `intel-sync` arguments.
#[derive(Debug, Args)]
pub struct IntelSyncArgs {
    /// Feed adapter(s) to sync. Repeatable; outputs are merged when multiple.
    #[arg(long = "source", value_name = "NAME", required = true)]
    sources: Vec<String>,

    /// Output JSON path (default: data/feeds/<source>.json, or merged.json).
    #[arg(long, short)]
    out: Option<PathBuf>,

    /// Override download URL for the `feodo` adapter.
    #[arg(long, default_value = feodo::DEFAULT_URL)]
    feodo_url: String,

    /// HTTP timeout in seconds.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

fn run_intel_sync(args: IntelSyncArgs) -> Result<()> {
    let timeout = Duration::from_secs(args.timeout);

    let mut feeds = Vec::new();
    for source in &args.sources {
        let feed = sync_source(source, &args.feodo_url, timeout)
            .with_context(|| format!("sync source {source}"))?;
        eprintln!("{source}: {} indicator(s)", feed.len());
        feeds.push(feed);
    }

    let (out_path, written) = if feeds.len() == 1 {
        let source = &args.sources[0];
        let path = args.out.clone().unwrap_or_else(|| default_out_path(source));
        sync::write_feed(&path, &feed_source_label(source), &feeds[0])?;
        (path, feeds[0].len())
    } else {
        let merged = sync::merge_feeds(&feeds);
        let path = args
            .out
            .clone()
            .unwrap_or_else(|| PathBuf::from("data/feeds/merged.json"));
        sync::write_feed(&path, "merged", &merged)?;
        (path, merged.len())
    };

    println!("wrote {} indicator(s) to {}", written, out_path.display());
    Ok(())
}

fn sync_source(name: &str, feodo_url: &str, timeout: Duration) -> Result<ThreatFeed> {
    match name {
        "feodo" => {
            let body = agent_cli_common::http::get_text(feodo_url, timeout)?;
            feodo::parse_json(&body)
        }
        other => bail!("unknown source {other:?} (supported: feodo)"),
    }
}

fn default_out_path(source: &str) -> PathBuf {
    PathBuf::from(format!("data/feeds/{source}.json"))
}

fn feed_source_label(source: &str) -> String {
    match source {
        "feodo" => feodo::SOURCE.to_string(),
        other => other.to_string(),
    }
}
