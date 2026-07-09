//! agent-respond: real-time protection daemon (standalone binary).
//!
//! Thin wrapper over [`agent_respond::cli`] — the same CLI the umbrella
//! `agentd respond` subcommand drives.

use agent_respond::cli::GuardArgs;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "agent-respond",
    version,
    about = "real-time protection: FIM, on-access malware, behavior, network IOC, IDS (detect + active response + report)"
)]
struct Cli {
    #[command(flatten)]
    args: GuardArgs,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Standalone: stdout / local NDJSON sinks only — no upload sink injected.
    // Uploading to analyzer is the `agentd respond --upload` umbrella's job.
    agent_respond::cli::run(cli.args, vec![])
}
