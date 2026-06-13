//! `agent-host` CLI: argument parsing + run, shared by the standalone
//! `agent-host` binary and the umbrella `agent host` subcommand.
//!
//! This layer only **produces results** (per-asset JSON files, or a merged
//! [`agent_contract::AssetReport`] written to stdout / `--report-out`). It does
//! **not** upload — uploading is the `agent` umbrella's job, which inspects the
//! returned report. Run standalone, `agent-host` is a pure local collector.

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use agent_contract::AssetReport;
use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

use crate::{
    default_collectors, platform, run_scan_at_with_opts, run_static_scan, Collector,
    ContainerScanOptions, MalwareCollector, NestedAssetsCollector, ScanOptions, ScanTarget,
    WindowsPackageProfile,
};

/// Host static file detection arguments (`agent-host` / `agent host`).
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Mounted filesystem root. Default: `/` on Linux, `%SystemDrive%\` on Windows.
    #[arg(long, short = 'r')]
    root: Option<PathBuf>,

    /// Scan object: host | packages | sbom | services | accounts | credentials | identity | all.
    #[arg(long, short = 't', default_value = "host")]
    target: String,

    /// Output DIR for per-asset JSON (`host.json`, …). Selects per-asset (static) mode.
    #[arg(long, short = 'o', value_name = "DIR")]
    output: Option<PathBuf>,

    /// Extra project dir (relative to --root) for language packages. Repeatable.
    #[arg(long = "project-root", value_name = "PATH")]
    project_root: Vec<PathBuf>,

    /// Windows package scope: `full` (include CBS updates) or `apps` (skip CBS).
    #[arg(long, value_name = "PROFILE", default_value = "full")]
    windows_packages: String,

    /// Pretty-print the merged AssetReport JSON to stdout (merged mode).
    #[arg(long)]
    pretty: bool,

    /// Write the merged AssetReport JSON to a file (merged mode).
    #[arg(long, value_name = "FILE")]
    report_out: Option<PathBuf>,

    /// Also run the built-in malware signature scan. Merged mode → into
    /// `vulnerabilities`; static mode (`-o DIR`) → also writes `malware.json`.
    #[arg(long)]
    malware: bool,

    /// Parallel malware scan workers.
    #[arg(long, default_value_t = crate::default_workers())]
    malware_jobs: usize,

    /// Extra malware signatures (JSON) loaded on top of the built-in set.
    #[arg(long, value_name = "PATH")]
    malware_signatures: Option<PathBuf>,

    /// Also scan inside discovered container rootfs (Docker / Podman / containerd / k8s).
    #[arg(long)]
    scan_containers: bool,

    /// Container asset categories when --scan-containers is set
    /// (comma list: packages,services,accounts,credentials,all). Default: packages,services.
    #[arg(long, value_name = "TARGETS")]
    container_asset_targets: Option<String>,

    /// Upper bound on containers scanned per host pass.
    #[arg(long, default_value_t = 64)]
    max_containers: usize,
}

/// Run the host static file detection per `args`.
///
/// Returns the merged [`AssetReport`] when run in merged mode (so the caller —
/// e.g. `agent host --upload` — can upload it), or `None` in per-asset (`-o DIR`)
/// mode, which only writes files.
pub fn run(args: ScanArgs) -> Result<Option<AssetReport>> {
    let scan_root = args
        .root
        .clone()
        .unwrap_or_else(platform::default_scan_root);
    let windows_packages = WindowsPackageProfile::parse(&args.windows_packages)?;

    // Per-asset (static) mode: one JSON file per category under `output`.
    if let Some(out_dir) = &args.output {
        let target = ScanTarget::parse(&args.target)?;
        let options = ScanOptions {
            root: scan_root.clone(),
            target,
            project_roots: args.project_root.clone(),
            windows_packages,
        };
        let written = run_static_scan(&options, out_dir).context("static scan")?;
        for path in written.written_paths() {
            eprintln!("wrote {}", path.display());
        }
        if args.malware {
            run_static_malware(&args, &scan_root, out_dir)?;
        }
        return Ok(None);
    }

    // Merged mode: assemble a collector plan → one AssetReport.
    let plan = build_plan(&args)?;
    anyhow::ensure!(!plan.is_empty(), "no collectors enabled");

    let report = run_scan_at_with_opts(
        &plan,
        &scan_root,
        args.project_root.clone(),
        windows_packages,
    )
    .context("running scan")?;

    write_json(&report, args.report_out.as_deref(), args.pretty)?;
    Ok(Some(report))
}

fn build_plan(args: &ScanArgs) -> anyhow::Result<Vec<Box<dyn Collector>>> {
    let mut plan: Vec<Box<dyn Collector>> = default_collectors();
    if args.malware {
        let mut malware = MalwareCollector::default().with_workers(args.malware_jobs);
        if let Some(path) = &args.malware_signatures {
            malware = malware.with_signatures(path.clone());
        }
        plan.push(Box::new(malware));
    }
    if args.scan_containers {
        let opts = ContainerScanOptions::from_cli(
            true,
            args.container_asset_targets.as_deref(),
            args.max_containers,
            true,
        )?;
        plan.push(Box::new(NestedAssetsCollector::new(opts)));
    }
    Ok(plan)
}

/// Run a standalone malware scan and write `malware.json` (`Vulnerability[]`)
/// into `out_dir`. `affected_asset_id` is the infected path here; the remote
/// assembler rebinds it to the host id.
fn run_static_malware(args: &ScanArgs, scan_root: &Path, out_dir: &Path) -> Result<()> {
    use crate::malware::{detection_to_vulnerability, run_scan, MalwareOptions, SignatureSet};

    let mut signatures = SignatureSet::builtin();
    if let Some(path) = &args.malware_signatures {
        signatures.load_extra(path)?;
    }

    let mut options = MalwareOptions::new(scan_root);
    options.signatures = Arc::new(signatures);
    options.workers = args.malware_jobs.max(1);

    let result = run_scan(&options).context("malware scan")?;
    let vulnerabilities: Vec<_> = result
        .detections
        .iter()
        .map(|d| detection_to_vulnerability(d, &d.path.to_string_lossy()))
        .collect();

    write_json(&vulnerabilities, Some(&out_dir.join("malware.json")), true)
}

/// Serialize `value` as JSON to a file (logging `wrote <path>`) or stdout.
fn write_json<T: Serialize>(value: &T, dest: Option<&Path>, pretty: bool) -> Result<()> {
    let payload = if pretty {
        serde_json::to_vec_pretty(value)?
    } else {
        serde_json::to_vec(value)?
    };
    match dest {
        Some(path) => {
            std::fs::write(path, &payload)
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&payload)?;
            stdout.write_all(b"\n")?;
        }
    }
    Ok(())
}
