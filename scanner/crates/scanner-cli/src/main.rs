//! scanner-cli: assemble a scan plan, run it, emit JSON (optionally upload).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use scanner_runtime::{run_scan_at_with, Collector};

#[derive(Debug, Parser)]
#[command(
    name = "scanner-cli",
    version,
    about = "cyber-posture host scanner: AssetReport or per-asset JSON files"
)]
struct Args {
    /// Mounted filesystem root (static scan).
    #[arg(long, short = 'r', default_value = "/")]
    root: PathBuf,

    /// Static scan object: host | packages | sbom | services | accounts |
    /// credentials | identity | all (writes per-asset JSON).
    #[arg(long, short = 't', default_value = "host")]
    target: String,

    /// Output directory for per-asset JSON (`host.json`, …). Enables static asset mode.
    #[arg(long)]
    asset_out: Option<PathBuf>,

    /// Extra project dir (relative to --root) to scan for language packages
    /// (venv / node_modules). Repeatable.
    #[arg(long = "project-root", value_name = "PATH")]
    project_root: Vec<PathBuf>,

    /// Pretty-print the combined AssetReport JSON (stdout).
    #[arg(long)]
    pretty: bool,

    /// Write combined AssetReport JSON to a file.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Upload report to form after scan (`/ingest/asset-report`; requires the
    /// `ingest` feature).
    #[arg(long)]
    upload: Option<String>,

    /// Parallel ClamAV workers when `malware` feature is enabled.
    #[cfg(feature = "malware")]
    #[arg(long, default_value_t = scanner_malware::default_workers())]
    malware_jobs: usize,
}

fn build_plan(
    #[cfg_attr(not(feature = "malware"), allow(unused_variables))] args: &Args,
) -> Vec<Box<dyn Collector>> {
    let mut plan: Vec<Box<dyn Collector>> = Vec::new();

    #[cfg(feature = "asset")]
    plan.extend(scanner_asset::default_collectors());

    #[cfg(feature = "malware")]
    plan.push(Box::new(
        scanner_malware::MalwareCollector::default().with_workers(args.malware_jobs),
    ));

    plan
}

fn main() -> Result<()> {
    let args = Args::parse();

    #[cfg(feature = "asset")]
    if let Some(out_dir) = &args.asset_out {
        let target = scanner_asset::ScanTarget::parse(&args.target)?;
        let options = scanner_asset::ScanOptions {
            root: args.root.clone(),
            target,
            project_roots: args.project_root.clone(),
        };
        let written = scanner_asset::run_static_scan(&options, out_dir).context("static scan")?;
        for path in written.written_paths() {
            eprintln!("wrote {}", path.display());
        }
        return Ok(());
    }

    let plan = build_plan(&args);
    anyhow::ensure!(
        !plan.is_empty(),
        "no collectors enabled (enable `asset` feature)"
    );

    let report =
        run_scan_at_with(&plan, &args.root, args.project_root.clone()).context("running scan")?;

    #[cfg(feature = "ingest")]
    if let Some(base) = &args.upload {
        scanner_ingest::upload_report(&report, base).context("uploading report")?;
    }

    #[cfg(not(feature = "ingest"))]
    if args.upload.is_some() {
        anyhow::bail!("rebuild with `--features ingest` to use --upload");
    }

    let payload = if args.pretty {
        serde_json::to_vec_pretty(&report)?
    } else {
        serde_json::to_vec(&report)?
    };

    match args.out {
        Some(path) => {
            std::fs::write(&path, &payload)
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => {
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&payload)?;
            stdout.write_all(b"\n")?;
        }
    }

    Ok(())
}
