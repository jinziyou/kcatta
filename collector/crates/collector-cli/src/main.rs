//! collector-cli: command-line driver around `collector-core::run_capture`.
//!
//! For v0 the CLI runs one capture cycle and emits the resulting
//! `FlowBatch` as JSON, either pretty-printed to stdout or written to a
//! file. Future versions will grow flags for selecting capture
//! interfaces, batch window, upload destinations, etc.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "collector-cli",
    version,
    about = "cyber-posture flow collector: produce a FlowBatch JSON"
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

    let batch = collector_core::run_capture().context("running capture")?;

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
