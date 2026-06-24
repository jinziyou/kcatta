//! `agent-host` CLI: argument parsing + run, shared by the standalone
//! `agent-host` binary and the umbrella `agentd host` subcommand.
//!
//! This layer only **produces results** (per-asset JSON files, or a merged
//! [`agent_contract::AssetReport`] written to stdout / `--report-out`). It does
//! **not** upload — uploading is the `agentd` umbrella's job, which inspects the
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
    ContainerScanOptions, ImagesCollector, MalwareCollector, NestedAssetsCollector,
    PostureCollector, ScanOptions, ScanTarget, WindowsPackageProfile,
};

/// Host static file detection arguments (`agent-host` / `agentd host`).
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Mounted filesystem root. Default: `/` on Linux, `%SystemDrive%\` on Windows.
    #[arg(long, short = 'r')]
    root: Option<PathBuf>,

    /// Scan a container image instead of a live filesystem: a `docker save` /
    /// OCI archive (`.tar`, optionally gzip). Its layers are assembled into a
    /// merged rootfs (static, no running container) and scanned like `--root`.
    /// Mutually exclusive with `--root`.
    #[arg(long, value_name = "ARCHIVE", conflicts_with = "root")]
    image: Option<PathBuf>,

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

    /// Also scan dependency/build/VCS trees (node_modules, site-packages,
    /// vendor, …) that are pruned by default — where supply-chain malware hides.
    #[arg(long)]
    malware_scan_deps: bool,

    /// Skip host security-posture checks (sshd_config / shadow / SUID misconfig).
    /// Posture runs by default on host scans; it is always skipped for `--image`.
    #[arg(long)]
    no_posture: bool,

    /// Deprecated/no-op: container + image asset collection is now ON by default
    /// when a runtime is detected. Accepted for backward compatibility.
    #[arg(long, hide = true)]
    scan_containers: bool,

    /// Disable the automatic container + image asset collection entirely.
    #[arg(long)]
    no_container_assets: bool,

    /// In-container asset categories
    /// (comma list: packages,services,accounts,credentials,all). Default: packages,services.
    #[arg(long, value_name = "TARGETS")]
    container_asset_targets: Option<String>,

    /// Upper bound on containers scanned per host pass.
    #[arg(long, default_value_t = 64)]
    max_containers: usize,

    /// Upper bound on local images assembled + scanned per host pass.
    #[arg(long, default_value_t = 32)]
    max_images: usize,

    /// Skip local image scanning (still scans inside running/stopped containers).
    #[arg(long)]
    no_image_assets: bool,

    /// Include non-running containers in nested scanning.
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
    include_stopped_containers: bool,
}

/// Run the host static file detection per `args`.
///
/// Returns the merged [`AssetReport`] when run in merged mode (so the caller —
/// e.g. `agentd host --upload` — can upload it), or `None` in per-asset (`-o DIR`)
/// mode, which only writes files.
pub fn run(args: ScanArgs) -> Result<Option<AssetReport>> {
    // `--image` assembles the image's layers into a merged rootfs in a tempdir and
    // scans that as the root. `_image_root` keeps the tempdir alive for the whole
    // scan (its Drop deletes it); bind it for the function body, not just here.
    let _image_root;
    let scan_root = if let Some(image) = &args.image {
        let staged = tempfile::tempdir().context("create image rootfs dir")?;
        crate::assemble_image_rootfs(image, staged.path())
            .with_context(|| format!("assembling image {}", image.display()))?;
        let root = staged.path().to_path_buf();
        _image_root = staged;
        root
    } else {
        args.root
            .clone()
            .unwrap_or_else(platform::default_scan_root)
    };
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
        let mut malware = MalwareCollector::default()
            .with_workers(args.malware_jobs)
            .with_scan_all_dirs(args.malware_scan_deps);
        if let Some(path) = &args.malware_signatures {
            malware = malware.with_signatures(path.clone());
        }
        plan.push(Box::new(malware));
    }
    // Host-posture misconfig checks. HOST scans only: an `--image` scan_root is an
    // assembled image rootfs, so a posture finding there would be wrongly
    // host-attributed — structurally exclude it (the finding anchors on host_id).
    if !args.no_posture && args.image.is_none() {
        plan.push(Box::new(PostureCollector));
    }
    // Container + image asset collection is automatic ("无感知"): when a runtime
    // is present under the scan root, scan inside containers AND enumerate local
    // images. Both collectors self-no-op when no runtime metadata is found, so
    // this is free on non-container hosts. `--no-container-assets` opts out;
    // `--container-asset-targets` / `--max-*` / `--no-image-assets` tune it.
    if !args.no_container_assets {
        let mut opts = match args.container_asset_targets.as_deref() {
            Some(raw) => ContainerScanOptions::parse_targets(raw)?,
            None => ContainerScanOptions::enabled(),
        };
        opts.max_containers = args.max_containers;
        opts.include_stopped = args.include_stopped_containers;
        opts.max_images = args.max_images;
        opts.scan_images = !args.no_image_assets;
        plan.push(Box::new(NestedAssetsCollector::new(opts.clone())));
        if opts.scan_images {
            plan.push(Box::new(ImagesCollector::new(opts)));
        }
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
    if args.malware_scan_deps {
        options.skip_dirs = Vec::new();
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap {
        #[command(flatten)]
        args: ScanArgs,
    }

    fn plan_ids(argv: &[&str]) -> Vec<&'static str> {
        let w = Wrap::try_parse_from(argv).unwrap();
        build_plan(&w.args)
            .unwrap()
            .iter()
            .map(|c| c.id())
            .collect()
    }

    #[test]
    fn posture_gated_to_host_scans() {
        // Default host scan -> posture present.
        assert!(plan_ids(&["x"]).contains(&"posture"));
        // --no-posture -> absent.
        assert!(!plan_ids(&["x", "--no-posture"]).contains(&"posture"));
        // --image (assembled rootfs) -> structurally absent (would mis-attribute).
        assert!(!plan_ids(&["x", "--image", "/tmp/none.tar"]).contains(&"posture"));
    }
}
