//! agent-trace: traffic detection (standalone binary).
//!
//! Thin wrapper over [`agent_trace::cli`] — the same CLI the umbrella `agentd flow`
//! subcommand drives. Subcommands: `capture` (mock | pcap → IOC match → TraceBatch)
//! and `intel-sync` (download IOC feeds). Independent binary: links neither the
//! host scan nor the guard daemon.

use agent_trace::cli::TraceCommand;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "agent-trace",
    version,
    about = "network trace capture + threat-intel IOC matching → TraceBatch"
)]
struct Cli {
    #[command(subcommand)]
    command: TraceCommand,
}

fn main() -> anyhow::Result<()> {
    // Standalone: capture/sync + write files only. Uploading is the `agentd` umbrella's job.
    agent_trace::cli::run(Cli::parse().command)?;
    Ok(())
}
