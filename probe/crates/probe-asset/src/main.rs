//! Standalone static asset scanner CLI.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use probe_asset::{run_static_scan, ScanOptions, ScanTarget, platform};
use probe_runtime::WindowsPackageProfile;

#[derive(Debug, Parser)]
#[command(
    name = "probe-asset",
    version,
    about = "Static filesystem asset scan → per-asset JSON files"
)]
struct Args {
    /// Mounted filesystem root to scan (default: `/` on Linux, `%SystemDrive%\` on Windows).
    #[arg(long, short = 'r')]
    root: Option<PathBuf>,

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

    /// Windows package scope: `full` (include CBS updates) or `apps` (skip CBS).
    #[arg(long, value_name = "PROFILE", default_value = "full")]
    windows_packages: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let target = ScanTarget::parse(&args.target)?;

    let windows_packages = WindowsPackageProfile::parse(&args.windows_packages)?;

    let options = ScanOptions {
        root: args.root.unwrap_or_else(platform::default_scan_root),
        target,
        project_roots: args.project_root,
        windows_packages,
    };

    let written = run_static_scan(&options, &args.output).context("static scan")?;

    for path in written.written_paths() {
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}
