//! `posture-guard` CLI: args + run, shared by the standalone `posture-guard`
//! binary and the umbrella `agent guard` subcommand.

use std::path::PathBuf;

use clap::Args;

use crate::{GuardConfig, Mode, Supervisor};

/// Real-time protection daemon arguments (`posture-guard` / `agent guard`).
#[derive(Debug, Args)]
pub struct GuardArgs {
    /// JSON config (sensors, watch paths, response policy). Missing → safe
    /// monitor-mode defaults so the daemon is runnable out of the box.
    #[arg(long, default_value = "/etc/posture/guard.json")]
    config: PathBuf,

    /// fusion base URL for real-time GuardEventBatch upload (overrides config).
    #[arg(long, value_name = "URL")]
    upload: Option<String>,

    /// Force monitor mode (detect + report only), overriding the config's mode.
    #[arg(long)]
    detect_only: bool,

    /// Also print each flushed batch to stdout (dev).
    #[arg(long)]
    stdout: bool,
}

/// Load config, apply CLI overrides, and run the daemon (blocks until shutdown).
pub fn run(args: GuardArgs) -> anyhow::Result<()> {
    let mut config = GuardConfig::load(&args.config)?;

    if let Some(url) = args.upload {
        config.report.upload = Some(url);
    }
    if args.detect_only {
        config.mode = Mode::Monitor;
    }
    if args.stdout {
        config.report.stdout = true;
    }

    Supervisor::new(config).run()
}
