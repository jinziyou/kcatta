//! collector-cli: command-line driver around `collector-core`.
//!
//! Runs one capture cycle, applies threat-intel IOC matching
//! (preliminary processing), then emits the resulting `FlowBatch` as
//! JSON and/or uploads it to form for correlation.
//!
//! Future versions will grow flags for selecting capture interfaces,
//! batch window, etc.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use collector_core::{run_capture_with_feed, ThreatFeed};

#[derive(Debug, Parser)]
#[command(
    name = "collector-cli",
    version,
    about = "cyber-posture flow collector: capture, threat-intel match, emit/upload a FlowBatch"
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
}

fn main() -> Result<()> {
    let args = Args::parse();

    let feed = match &args.intel {
        Some(path) => ThreatFeed::from_json_path(path).context("loading threat-intel feed")?,
        None => ThreatFeed::builtin(),
    };

    let batch = run_capture_with_feed(&feed).context("running capture")?;

    if let Some(base) = &args.upload {
        collector_ingest::upload_batch(&batch, base).context("uploading batch")?;
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
