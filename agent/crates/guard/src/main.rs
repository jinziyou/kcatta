//! posture-guard: real-time protection daemon (the 实时防护 capability).
//!
//! A long-running endpoint sensor that detects (FIM, on-access malware, process
//! behavior, network IOC, IDS), optionally takes config-gated active response,
//! and reports `GuardEventBatch`es to fusion + a local audit log.
//!
//! Safe by default — monitor mode, no destructive action — until enforcement is
//! deliberately enabled in the config.

use std::path::PathBuf;

use clap::Parser;
use posture_guard::{GuardConfig, Mode, Supervisor};

#[derive(Debug, Parser)]
#[command(
    name = "posture-guard",
    version,
    about = "real-time protection: FIM, on-access malware, behavior, network IOC, IDS (detect + active response + report)"
)]
struct Cli {
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut config = GuardConfig::load(&cli.config)?;

    if let Some(url) = cli.upload {
        config.report.upload = Some(url);
    }
    if cli.detect_only {
        config.mode = Mode::Monitor;
    }
    if cli.stdout {
        config.report.stdout = true;
    }

    Supervisor::new(config).run()
}
