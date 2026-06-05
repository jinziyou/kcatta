//! probe-flow-cli: command-line driver around `probe-flow`.
//!
//! Runs one capture cycle, applies threat-intel IOC matching
//! (preliminary processing), then emits the resulting `FlowBatch` as
//! JSON and/or uploads it to form for correlation.

use std::path::PathBuf;

#[cfg(not(feature = "pcap"))]
use anyhow::bail;
use anyhow::{Context, Result};
use clap::Parser;
use probe_flow::{run_capture_with_config, CaptureConfig, ThreatFeed};

#[derive(Debug, Parser)]
#[command(
    name = "probe-flow",
    version,
    about = "posture flow collector: capture, threat-intel match, emit/upload a FlowBatch"
)]
struct Args {
    /// Pretty-print the JSON output (default: compact).
    #[arg(long)]
    pretty: bool,

    /// Write JSON to a file instead of stdout.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Threat-intel IOC feed (JSON) to match flows against. Defaults to a
    /// small built-in demo feed when omitted.
    #[arg(long, value_name = "PATH")]
    intel: Option<PathBuf>,

    /// Upload the batch to form after capture (`<URL>/ingest/flow-batch`),
    /// e.g. --upload http://127.0.0.1:8000.
    #[arg(long, value_name = "URL")]
    upload: Option<String>,

    /// Use synthetic mock flows instead of live capture (default).
    #[arg(long, conflicts_with_all = ["pcap", "iface", "duration", "bpf"])]
    mock: bool,

    /// Capture live traffic via libpcap (requires `--features pcap` at build).
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

    /// List libpcap capture devices and exit (requires `--features pcap`).
    #[cfg(feature = "pcap")]
    #[arg(long)]
    list_devices: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    #[cfg(feature = "pcap")]
    if args.list_devices {
        let names = probe_flow::pcap::list_devices().context("list pcap devices")?;
        for name in names {
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
        probe_ingest::upload_batch(&batch, base).context("uploading batch")?;
        let hits: usize = batch.flows.iter().map(|f| f.threat_intel.len()).sum();
        eprintln!(
            "uploaded {} ({} flow(s), {} threat-intel hit(s)) to {base}",
            batch.batch_id,
            batch.flows.len(),
            hits,
        );
    }

    let payload = if args.pretty {
        serde_json::to_vec_pretty(&batch)?
    } else {
        serde_json::to_vec(&batch)?
    };

    match args.out {
        Some(path) => {
            std::fs::write(&path, &payload)
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => {
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&payload)?;
            stdout.write_all(b"\n")?;
        }
    }

    Ok(())
}

fn build_capture_config(args: &Args) -> Result<CaptureConfig> {
    if args.mock || !args.pcap {
        return Ok(CaptureConfig::mock());
    }

    #[cfg(feature = "pcap")]
    {
        return Ok(CaptureConfig::pcap(
            args.iface.clone(),
            args.duration,
            args.bpf.clone(),
        ));
    }

    #[cfg(not(feature = "pcap"))]
    {
        let _ = args;
        bail!("rebuild with `--features pcap` to use live capture (--pcap)")
    }
}
