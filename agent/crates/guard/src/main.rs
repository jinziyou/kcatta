//! agent-guard: real-time protection daemon (standalone binary).
//!
//! Thin wrapper over [`agent_guard::cli`] — the same CLI the umbrella `agent guard`
//! subcommand drives. Detects (FIM, on-access malware, process behavior, network
//! IOC, IDS), optionally takes config-gated active response, and reports
//! `GuardEventBatch`es. Safe by default (monitor mode). Independent binary.

use clap::Parser;
use agent_guard::cli::GuardArgs;

#[derive(Debug, Parser)]
#[command(
    name = "agent-guard",
    version,
    about = "real-time protection: FIM, on-access malware, behavior, network IOC, IDS (detect + active response + report)"
)]
struct Cli {
    #[command(flatten)]
    args: GuardArgs,
}

fn main() -> anyhow::Result<()> {
    // Standalone: stdout / local NDJSON sinks only — no upload sink injected.
    // Uploading to fusion is the `agent guard --upload` umbrella's job.
    agent_guard::cli::run(Cli::parse().args, vec![])
}
