//! `agent-guard` CLI: args + run, shared by the standalone `agent-guard`
//! binary and the umbrella `agentd guard` subcommand.

use std::path::PathBuf;

use clap::Args;

use crate::{GuardConfig, Mode, ReportSink, Supervisor};

/// Real-time protection daemon arguments (`agent-guard` / `agentd guard`).
#[derive(Debug, Args)]
pub struct GuardArgs {
    /// JSON config (sensors, watch paths, response policy). Missing → safe
    /// monitor-mode defaults so the daemon is runnable out of the box.
    #[arg(long, default_value = "/etc/kcatta/guard.json")]
    config: PathBuf,

    /// Force monitor mode (detect + report only), overriding the config's mode.
    #[arg(long)]
    detect_only: bool,

    /// Also print each flushed batch to stdout (dev).
    #[arg(long)]
    stdout: bool,

    /// Remove a single IP from the netblock deny set and exit (does not start the
    /// daemon). Reverses an `nft`-backend block; eBPF blocks clear on daemon exit.
    #[arg(long, value_name = "IP")]
    unblock: Option<String>,

    /// Remove every IP from the netblock deny set and exit (does not start the daemon).
    #[arg(long)]
    unblock_all: bool,
}

/// Load config, apply CLI overrides, and run the daemon (blocks until shutdown).
///
/// `extra_sinks` are caller-injected report destinations (e.g. the `agentd guard
/// --upload` analyzer sink). The standalone `agent-guard` binary passes none, so
/// it only writes the local NDJSON audit / stdout — it never uploads.
pub fn run(args: GuardArgs, extra_sinks: Vec<Box<dyn ReportSink>>) -> anyhow::Result<()> {
    // Management actions short-circuit before any daemon setup.
    if args.unblock_all {
        crate::respond::netblock_unblock_all()?;
        eprintln!("guard: cleared all netblock entries");
        return Ok(());
    }
    if let Some(ip) = args.unblock.as_deref() {
        crate::respond::netblock_unblock(ip)?;
        eprintln!("guard: unblocked {ip}");
        return Ok(());
    }

    let mut config = GuardConfig::load(&args.config)?;

    if args.detect_only {
        config.mode = Mode::Monitor;
    }
    if args.stdout {
        config.report.stdout = true;
    }

    Supervisor::new(config, extra_sinks).run()
}
