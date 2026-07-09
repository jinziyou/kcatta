//! agent-collect-trace: network/file/process collection (standalone binary).
//!
//! Thin wrapper over [`agent_collect_trace::cli`] — the same CLI the umbrella
//! `agentd collect-trace` subcommand drives.

use agent_collect_trace::cli::TraceCommand;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "agent-collect-trace",
    version,
    about = "network trace capture + threat-intel IOC matching → TraceBatch"
)]
struct Cli {
    #[command(subcommand)]
    command: TraceCommand,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Standalone: capture/sync + write files only. Uploading is the `agentd` umbrella's job.
    agent_collect_trace::cli::run(cli.command)?;
    Ok(())
}
