//! posture-flow: traffic detection (standalone binary).
//!
//! Thin wrapper over [`posture_flow::cli`] — the same CLI the umbrella `agent flow`
//! subcommand drives. Subcommands: `capture` (mock | pcap → IOC match → FlowBatch)
//! and `intel-sync` (download IOC feeds). Independent binary: links neither the
//! host scan nor the guard daemon.

use clap::Parser;
use posture_flow::cli::FlowCommand;

#[derive(Debug, Parser)]
#[command(
    name = "posture-flow",
    version,
    about = "network flow capture + threat-intel IOC matching → FlowBatch"
)]
struct Cli {
    #[command(subcommand)]
    command: FlowCommand,
}

fn main() -> anyhow::Result<()> {
    // Standalone: capture/sync + write files only. Uploading is the `agent` umbrella's job.
    posture_flow::cli::run(Cli::parse().command)?;
    Ok(())
}
