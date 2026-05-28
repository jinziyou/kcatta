//! scanner-cli: command-line driver around `scanner-core::run_scan`.
//!
//! For v0 the CLI does one thing: run a scan and emit the resulting
//! `AssetReport` as JSON, either pretty-printed to stdout or written to
//! a file. Future versions will grow flags for selecting which
//! collectors to run, where to upload, etc.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

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
}

fn main() -> Result<()> {
    let args = Args::parse();

    let report = scanner_core::run_scan().context("running scan")?;

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
