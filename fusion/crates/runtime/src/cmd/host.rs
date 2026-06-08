//! `fusion host`: host asset detection.
//!
//! Two output modes:
//! - **per-asset (static)**: `-o DIR` writes `host.json`, `packages.json`, … via
//!   [`run_static_scan`]; with `--malware` it also writes `malware.json`. This is
//!   the mode `form-scan` drives on a target.
//! - **merged**: no `-o` → assemble a collector plan into a single
//!   [`fusion_contract::AssetReport`] (stdout / `--report-out` / `--upload`).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use fusion_host::{
    platform, run_scan_at_with_opts, run_static_scan, Collector, ScanOptions, ScanTarget,
    WindowsPackageProfile,
};

#[derive(Debug, Args)]
pub struct HostArgs {
    /// Mounted filesystem root. Default: `/` on Linux, `%SystemDrive%\` on Windows.
    #[arg(long, short = 'r')]
    root: Option<PathBuf>,

    /// Scan object: host | packages | sbom | services | accounts | credentials | identity | all.
    #[arg(long, short = 't', default_value = "host")]
    target: String,

    /// Output DIR for per-asset JSON (`host.json`, …). Selects per-asset (static) mode.
    #[arg(long, short = 'o', value_name = "DIR")]
    output: Option<PathBuf>,

    /// Extra project dir (relative to --root) for language packages (venv /
    /// node_modules). Repeatable.
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

    /// Upload the merged AssetReport to form (`<URL>/ingest/asset-report`).
    #[arg(long, value_name = "URL")]
    upload: Option<String>,

    /// Also run a ClamAV INSTREAM scan (needs `clamd`). Merged mode → merged into
    /// `vulnerabilities`; static mode (`-o DIR`) → also writes `malware.json`.
    #[cfg(feature = "malware")]
    #[arg(long)]
    malware: bool,

    /// Parallel ClamAV workers.
    #[cfg(feature = "malware")]
    #[arg(long, default_value_t = fusion_host::default_workers())]
    malware_jobs: usize,

    /// clamd Unix socket path (overrides auto-detection).
    #[cfg(feature = "malware")]
    #[arg(long, value_name = "PATH")]
    clamd_socket: Option<PathBuf>,
}

pub fn run(args: HostArgs) -> Result<()> {
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
        #[cfg(feature = "malware")]
        if args.malware {
            let path = run_static_malware(&args, &scan_root, out_dir)?;
            eprintln!("wrote {}", path.display());
        }
        return Ok(());
    }

    // Merged mode: assemble a collector plan → one AssetReport.
    let plan = build_plan(&args);
    anyhow::ensure!(!plan.is_empty(), "no collectors enabled");

    let report = run_scan_at_with_opts(
        &plan,
        &scan_root,
        args.project_root.clone(),
        windows_packages,
    )
    .context("running scan")?;

    if let Some(base) = &args.upload {
        fusion_ingest::upload_report(&report, base).context("uploading report")?;
        eprintln!("uploaded report to {base}");
    }

    let payload = if args.pretty {
        serde_json::to_vec_pretty(&report)?
    } else {
        serde_json::to_vec(&report)?
    };
    match &args.report_out {
        Some(path) => {
            std::fs::write(path, &payload)
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

fn build_plan(
    #[cfg_attr(not(feature = "malware"), allow(unused_variables))] args: &HostArgs,
) -> Vec<Box<dyn Collector>> {
    #[cfg_attr(not(feature = "malware"), allow(unused_mut))]
    let mut plan: Vec<Box<dyn Collector>> = fusion_host::default_collectors();

    #[cfg(feature = "malware")]
    if args.malware {
        let mut malware = fusion_host::MalwareCollector::default().with_workers(args.malware_jobs);
        if let Some(sock) = &args.clamd_socket {
            malware = malware.with_address(fusion_host::malware::ClamdAddress::Unix(sock.clone()));
        }
        plan.push(Box::new(malware));
    }

    plan
}

/// Run a standalone ClamAV scan and write `malware.json` (`Vulnerability[]`) into
/// `out_dir`, mirroring the per-asset static files. `affected_asset_id` is the
/// infected path here; the remote assembler rebinds it to the host id.
#[cfg(feature = "malware")]
fn run_static_malware(
    args: &HostArgs,
    scan_root: &std::path::Path,
    out_dir: &std::path::Path,
) -> Result<PathBuf> {
    use fusion_host::malware::{
        detection_to_vulnerability, run_scan, ClamdAddress, MalwareOptions,
    };

    let mut options = MalwareOptions::new(scan_root);
    options.workers = args.malware_jobs.max(1);
    if let Some(sock) = &args.clamd_socket {
        options.address = ClamdAddress::Unix(sock.clone());
    }

    let result = run_scan(&options).context("clamav scan")?;
    let vulnerabilities: Vec<_> = result
        .detections
        .iter()
        .map(|d| detection_to_vulnerability(d, &d.path.to_string_lossy()))
        .collect();

    let path = out_dir.join("malware.json");
    let file =
        std::fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(file, &vulnerabilities)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}
