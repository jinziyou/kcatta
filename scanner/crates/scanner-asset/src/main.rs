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

    /// Scan object: host | packages | sbom | services | accounts | credentials | identity | all.
    #[arg(long, short = 't', default_value = "host")]
    target: String,

    /// Output directory for JSON files.
    #[arg(long, short = 'o', default_value = ".")]
    output: PathBuf,

    /// Extra project dir (relative to --root) to scan for language packages
    /// (venv / node_modules). Repeatable.
    #[arg(long = "project-root", value_name = "PATH")]
    project_root: Vec<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let target = ScanTarget::parse(&args.target)?;

    let options = ScanOptions {
        root: args.root,
        target,
        project_roots: args.project_root,
    };

    let written = run_static_scan(&options, &args.output).context("static scan")?;

    for path in written.written_paths() {
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}
