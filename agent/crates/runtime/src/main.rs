//! `agent`: posture collection orchestrator.
//!
//! One binary that schedules agent's detection modules as subcommands:
//! `host` (asset scan), `flow` (network capture), `intel-sync` (IOC feed
//! download). Each subcommand is gated by a cargo feature so a lean build can
//! drop unused domains and their dependency surface (e.g. a host-only agent
//! built with `--no-default-features --features host,malware` drops the
//! flow/pcap capture surface). The ingest HTTP client is still linked in any
//! build that includes a domain, since both `host --upload` and `flow --upload`
//! post to fusion over HTTP.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod cmd;

#[derive(Debug, Parser)]
#[command(
    name = "agent",
    version,
    about = "posture collection orchestrator: schedule host / flow / intel-sync modules"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Host asset detection: per-asset JSON files (`-o DIR`) or a merged
    /// AssetReport (stdout / `--upload`), with optional ClamAV.
    #[cfg(feature = "host")]
    Host(cmd::host::HostArgs),
    /// Network flow capture + threat-intel IOC matching → FlowBatch.
    #[cfg(feature = "flow")]
    Flow(cmd::flow::FlowArgs),
    /// Download threat-intel IOC feeds into local JSON for `agent flow --intel`.
    #[cfg(feature = "flow")]
    IntelSync(cmd::intel_sync::IntelSyncArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        #[cfg(feature = "host")]
        Command::Host(args) => cmd::host::run(args),
        #[cfg(feature = "flow")]
        Command::Flow(args) => cmd::flow::run(args),
        #[cfg(feature = "flow")]
        Command::IntelSync(args) => cmd::intel_sync::run(args),
    }
}
