//! `agent-guard` CLI: args + run, shared by the standalone `agent-guard`
//! binary and the umbrella `agent guard` subcommand.

use std::path::PathBuf;

use clap::Args;

use crate::{GuardConfig, Mode, ReportSink, Supervisor};

/// Real-time protection daemon arguments (`agent-guard` / `agent guard`).
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
}

/// Load config, apply CLI overrides, and run the daemon (blocks until shutdown).
///
/// `extra_sinks` are caller-injected report destinations (e.g. the `agent guard
/// --upload` fusion sink). The standalone `agent-guard` binary passes none, so
/// it only writes the local NDJSON audit / stdout — it never uploads.
pub fn run(args: GuardArgs, extra_sinks: Vec<Box<dyn ReportSink>>) -> anyhow::Result<()> {
    let mut config = GuardConfig::load(&args.config)?;

    if args.detect_only {
        config.mode = Mode::Monitor;
    }
    if args.stdout {
        config.report.stdout = true;
    }

    Supervisor::new(config, extra_sinks).run()
}
