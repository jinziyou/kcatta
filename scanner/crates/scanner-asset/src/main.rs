//! Standalone static asset scanner CLI.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use scanner_asset::{run_static_scan, ScanOptions, ScanTarget};

#[derive(Debug, Parser)]
#[command(
    name = "scanner-asset",
    version,
    about = "Static filesystem asset scan → per-asset JSON files"
)]
struct Args {
    /// Mounted filesystem root to scan.
    #[arg(long, short = 'r', default_value = "/")]
    root: PathBuf,

    /// Scan object: host | packages | sbom | all.
    #[arg(long, short = 't', default_value = "host")]
    target: String,

    /// Output directory for JSON files.
    #[arg(long, short = 'o', default_value = ".")]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let target = ScanTarget::parse(&args.target)?;

    let options = ScanOptions {
        root: args.root,
        target,
    };

    let written = run_static_scan(&options, &args.output).context("static scan")?;

    for path in [&written.host, &written.packages, &written.sbom]
        .into_iter()
        .flatten()
    {
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}
