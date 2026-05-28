//! scanner-cli: assemble a scan plan, run it, emit JSON (optionally upload).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use scanner_runtime::{run_scan, Collector};

#[derive(Debug, Parser)]
#[command(
    name = "scanner-cli",
    version,
    about = "cyber-posture host scanner: produce an AssetReport JSON"
)]
struct Args {
    /// Pretty-print the JSON output (default: compact).
    #[arg(long)]
    pretty: bool,

    /// Write JSON to a file instead of stdout.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Upload report to form after scan (requires `ingest` feature; not implemented).
    #[arg(long)]
    upload: Option<String>,
}

fn build_plan() -> Vec<Box<dyn Collector>> {
    let mut plan: Vec<Box<dyn Collector>> = Vec::new();

    #[cfg(feature = "asset")]
    plan.extend(scanner_asset::default_collectors());

    #[cfg(feature = "vuln")]
    plan.push(Box::new(scanner_vuln::VulnCollector));

    #[cfg(feature = "malware")]
    plan.push(Box::new(scanner_malware::MalwareCollector));

    plan
}

fn main() -> Result<()> {
    let args = Args::parse();

    let plan = build_plan();
    anyhow::ensure!(!plan.is_empty(), "no collectors enabled (enable `asset` feature)");

    let report = run_scan(&plan).context("running scan")?;

    #[cfg(feature = "ingest")]
    if let Some(base) = &args.upload {
        scanner_ingest::upload_report(&report, base).context("uploading report")?;
    }

    #[cfg(not(feature = "ingest"))]
    if args.upload.is_some() {
        anyhow::bail!("rebuild with `--features ingest` to use --upload");
    }

    let payload = if args.pretty {
        serde_json::to_vec_pretty(&report)?
    } else {
        serde_json::to_vec(&report)?
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
