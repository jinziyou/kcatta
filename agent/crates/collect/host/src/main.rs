//! agent-collect-host: host static asset collection (standalone binary).
//!
//! Thin wrapper over [`agent_collect_host::cli`] — the same CLI the umbrella
//! `agentd collect-host` subcommand drives.

use agent_collect_host::cli::ScanArgs;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "agent-collect-host",
    version,
    about = "host static file detection: per-asset JSON or merged AssetReport, with optional malware scan"
)]
struct Cli {
    #[command(flatten)]
    args: ScanArgs,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Standalone: collect + write files only. Uploading is the `agentd` umbrella's job.
    agent_collect_host::cli::run(cli.args)?;
    Ok(())
}
