//! posture-host: host static file detection (standalone binary).
//!
//! Thin wrapper over [`posture_host::cli`] — the same CLI the umbrella `agent host`
//! subcommand drives. Reads a mounted filesystem root and produces per-asset JSON
//! (`-o DIR`) or a merged [`posture_host::AssetReport`]; `--malware` adds the
//! built-in signature scan. Independent binary: links neither flow nor guard.

use clap::Parser;
use posture_host::cli::ScanArgs;

#[derive(Debug, Parser)]
#[command(
    name = "posture-host",
    version,
    about = "host static file detection: per-asset JSON or merged AssetReport, with optional malware scan"
)]
struct Cli {
    #[command(flatten)]
    args: ScanArgs,
}

fn main() -> anyhow::Result<()> {
    // Standalone: collect + write files only. Uploading is the `agent` umbrella's job.
    posture_host::cli::run(Cli::parse().args)?;
    Ok(())
}
