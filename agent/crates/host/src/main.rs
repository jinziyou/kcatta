//! agent-host: host static file detection (standalone binary).
//!
//! Thin wrapper over [`agent_host::cli`] — the same CLI the umbrella `agentd host`
//! subcommand drives. Reads a mounted filesystem root and produces per-asset JSON
//! (`-o DIR`) or a merged [`agent_host::AssetReport`]; `--malware` adds the
//! built-in signature scan. Independent binary: links neither flow nor guard.

use agent_host::cli::ScanArgs;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "agent-host",
    version,
    about = "host static file detection: per-asset JSON or merged AssetReport, with optional malware scan"
)]
struct Cli {
    #[command(flatten)]
    args: ScanArgs,
}

fn main() -> anyhow::Result<()> {
    // Standalone: collect + write files only. Uploading is the `agentd` umbrella's job.
    agent_host::cli::run(Cli::parse().args)?;
    Ok(())
}
