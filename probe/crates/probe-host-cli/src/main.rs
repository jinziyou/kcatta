//! probe-host-cli: assemble a scan plan, run it, emit JSON (optionally upload).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use probe_runtime::{run_scan_at_with_opts, Collector, WindowsPackageProfile};

#[derive(Debug, Parser)]
#[command(
    name = "probe-host",
    version,
    about = "posture host scanner: AssetReport or per-asset JSON files"
)]
struct Args {
    /// Mounted filesystem root (static scan). Default: `/` on Linux, `%SystemDrive%\` on Windows.
    #[arg(long, short = 'r')]
    root: Option<PathBuf>,

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

    /// Windows package scope: `full` (include CBS updates) or `apps` (skip CBS).
    #[arg(long, value_name = "PROFILE", default_value = "full")]
    windows_packages: String,

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
    #[arg(long, default_value_t = probe_malware::default_workers())]
    malware_jobs: usize,
}

fn build_plan(
    #[cfg_attr(not(feature = "malware"), allow(unused_variables))] args: &Args,
) -> Vec<Box<dyn Collector>> {
    let mut plan: Vec<Box<dyn Collector>> = Vec::new();

    #[cfg(feature = "asset")]
    plan.extend(probe_asset::default_collectors());

    #[cfg(feature = "malware")]
    plan.push(Box::new(
        probe_malware::MalwareCollector::default().with_workers(args.malware_jobs),
    ));

    plan
}

fn main() -> Result<()> {
    let args = Args::parse();
    let scan_root = args
        .root
        .clone()
        .unwrap_or_else(probe_asset::platform::default_scan_root);

    let windows_packages = WindowsPackageProfile::parse(&args.windows_packages)?;

    #[cfg(feature = "asset")]
    if let Some(out_dir) = &args.asset_out {
        let target = probe_asset::ScanTarget::parse(&args.target)?;
        let options = probe_asset::ScanOptions {
            root: scan_root.clone(),
            target,
            project_roots: args.project_root.clone(),
            windows_packages,
        };
        let written = probe_asset::run_static_scan(&options, out_dir).context("static scan")?;
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

    let report = run_scan_at_with_opts(
        &plan,
        &scan_root,
        args.project_root.clone(),
        windows_packages,
    )
    .context("running scan")?;

    #[cfg(feature = "ingest")]
    if let Some(base) = &args.upload {
        probe_ingest::upload_report(&report, base).context("uploading report")?;
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
