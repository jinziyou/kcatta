//! `agent-collect-host` CLI: argument parsing + run, shared by the standalone
//! `agent-collect-host` binary and the umbrella `agentd collect-host` subcommand
//! (short alias: `agentd host`).
//! This layer only **produces results** (per-asset JSON files, or a merged
//! [`agent_contract::AssetReport`] written to stdout / `--report-out`). It does
//! **not** upload — uploading is the `agentd` umbrella's job, which inspects the
//! returned report. Run standalone, `agent-collect-host` is a pure local collector.

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use agent_contract::{Asset, AssetReport, DetectorRun, HostInfo, Vulnerability};
use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

use crate::{
    platform, run_scan_at_with_opts, run_static_scan, ContainerScanOptions, FilesystemSource,
    ScanOptions, ScanTarget, Source, WindowsPackageProfile,
};
use agent_detect::host::{DetectOptions, MalwareDetectOptions};

/// Host static file detection arguments (`agent-collect-host` / `agentd collect-host`).
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

    /// Disable bounded auto-discovery of Python/npm project roots. Explicit
    /// --project-root values and fixed global package locations still apply.
    #[arg(long)]
    no_project_discovery: bool,

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
    #[arg(long, default_value_t = agent_detect::malware::default_workers())]
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

    /// Scan the filesystem for leaked secrets (plaintext private keys, cloud/
    /// provider tokens, credential files). Opt-in (walks + reads small files);
    /// always skipped for `--image`. Findings carry no plaintext secret.
    #[arg(long)]
    secrets: bool,

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
/// e.g. `agentd collect-host --upload` — can upload it), or `None` in per-asset
/// (`-o DIR`) mode, which only writes files.
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
        // Form's default `all` scan must use the same complete source plan as
        // merged uploads.  The older category-by-category static path omitted
        // ports, containers, images and the entire detect phase.
        if target == ScanTarget::All {
            run_static_all(&args, &scan_root, out_dir, windows_packages)?;
            return Ok(None);
        }
        let options = ScanOptions {
            root: scan_root.clone(),
            target,
            project_roots: args.project_root.clone(),
            project_discovery: !args.no_project_discovery,
            windows_packages,
        };
        let written = run_static_scan(&options, out_dir).context("static scan")?;
        for path in written.written_paths() {
            eprintln!("wrote {}", path.display());
        }
        if let Some(host_path) = written.host.as_deref() {
            run_static_detect(&args, &scan_root, out_dir, host_path)?;
        } else if args.malware {
            // Preserve the standalone CLI's historical `--malware` behavior
            // for non-report targets such as `packages`.
            run_static_malware(&args, &scan_root, out_dir)?;
        }
        return Ok(None);
    }

    // Merged mode: asset collectors → detect phase → one AssetReport.
    let plan = build_asset_plan(&args)?;
    anyhow::ensure!(!plan.is_empty(), "no collectors enabled");
    let detect = build_detect_opts(&args);

    // The standalone CLI is a composition facade: keep the SOC stages visible
    // even though both execute in this process.
    let mut report = run_scan_at_with_opts(
        &plan,
        &scan_root,
        args.project_root.clone(),
        windows_packages,
        !args.no_project_discovery,
    )
    .context("collecting host inventory")?;
    if detect.any_enabled() {
        let findings = agent_detect::host::detect(&scan_root, &report.host.host_id, &detect)
            .context("detecting host findings")?;
        report.detector_runs = Some(agent_detect::host::completed_runs(&detect, &findings));
        report.vulnerabilities.extend(findings);
    } else {
        report.detector_runs = Some(Vec::new());
    }
    report.normalize_wire_fields()?;
    if args.report_out.is_some() {
        report.validate_envelope_list_bounds()?;
    }

    write_json(&report, args.report_out.as_deref(), args.pretty)?;
    Ok(Some(report))
}

/// Run the complete inventory + detect plan used by Form's static `all` path,
/// then write one file for every wire-level asset kind.  Empty categories are
/// written as `[]`, making a missing artifact distinguishable from "scanned,
/// none found".
fn run_static_all(
    args: &ScanArgs,
    scan_root: &Path,
    out_dir: &Path,
    windows_packages: WindowsPackageProfile,
) -> Result<()> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating static output dir {}", out_dir.display()))?;

    let plan = build_asset_plan(args)?;
    anyhow::ensure!(!plan.is_empty(), "no collectors enabled");
    let mut report = run_scan_at_with_opts(
        &plan,
        scan_root,
        args.project_root.clone(),
        windows_packages,
        !args.no_project_discovery,
    )
    .context("collecting complete static host inventory")?;

    let detect = build_detect_opts(args);
    if detect.any_enabled() {
        let findings = agent_detect::host::detect(scan_root, &report.host.host_id, &detect)
            .context("detecting static host findings")?;
        report.detector_runs = Some(agent_detect::host::completed_runs(&detect, &findings));
        report.vulnerabilities.extend(findings);
    } else {
        report.detector_runs = Some(Vec::new());
    }
    report.normalize_wire_fields()?;

    write_json(&report.host, Some(&out_dir.join("host.json")), true)?;
    write_static_assets(&report.assets, out_dir)?;
    write_static_findings(&report.vulnerabilities, args.malware, out_dir)?;
    write_static_detector_runs(report.detector_runs.as_deref().unwrap_or_default(), out_dir)?;
    Ok(())
}

/// Write the seven asset categories represented by the shared wire contract.
fn write_static_assets(assets: &[Asset], out_dir: &Path) -> Result<()> {
    let categories = [
        ("packages.json", "package"),
        ("services.json", "service"),
        ("ports.json", "port"),
        ("accounts.json", "account"),
        ("credentials.json", "credential"),
        ("containers.json", "container"),
        ("images.json", "image"),
    ];
    for (filename, kind) in categories {
        let rows: Vec<&Asset> = assets
            .iter()
            .filter(|asset| static_asset_kind(asset) == kind)
            .collect();
        write_json(&rows, Some(&out_dir.join(filename)), true)?;
    }
    Ok(())
}

fn static_asset_kind(asset: &Asset) -> &'static str {
    match asset {
        Asset::Package(_) => "package",
        Asset::Service(_) => "service",
        Asset::Port(_) => "port",
        Asset::Account(_) => "account",
        Asset::Credential(_) => "credential",
        Asset::Container(_) => "container",
        Asset::Image(_) => "image",
        Asset::SecurityProduct(_) => "security_product",
    }
}

/// Run posture (default), optional malware and optional secret detection for a
/// static host report.  Findings are host-attributed and share the same file
/// contract as the complete `all` path.
fn run_static_detect(
    args: &ScanArgs,
    scan_root: &Path,
    out_dir: &Path,
    host_path: &Path,
) -> Result<()> {
    let host: HostInfo = serde_json::from_slice(
        &std::fs::read(host_path).with_context(|| format!("reading {}", host_path.display()))?,
    )
    .with_context(|| format!("parsing {}", host_path.display()))?;
    let detect = build_detect_opts(args);
    let findings = if detect.any_enabled() {
        agent_detect::host::detect(scan_root, &host.host_id, &detect)
            .context("detecting static host findings")?
    } else {
        Vec::new()
    };
    let runs = agent_detect::host::completed_runs(&detect, &findings);
    write_static_findings(&findings, args.malware, out_dir)?;
    write_static_detector_runs(&runs, out_dir)
}

fn write_static_findings(
    findings: &[Vulnerability],
    malware_enabled: bool,
    out_dir: &Path,
) -> Result<()> {
    write_json(findings, Some(&out_dir.join("findings.json")), true)?;
    if malware_enabled {
        // Keep malware.json for standalone/backward-compatible consumers while
        // Form reads findings.json as the canonical, non-duplicated stream.
        let malware: Vec<&Vulnerability> = findings
            .iter()
            .filter(|finding| finding.source == "kcatta-malware")
            .collect();
        write_json(&malware, Some(&out_dir.join("malware.json")), true)?;
    }
    Ok(())
}

fn write_static_detector_runs(runs: &[DetectorRun], out_dir: &Path) -> Result<()> {
    write_json(runs, Some(&out_dir.join("detector-runs.json")), true)
}

/// Asset-only collector plan (no malware / posture / secrets).
fn build_asset_plan(args: &ScanArgs) -> anyhow::Result<Vec<Box<dyn Source>>> {
    // Container + image asset collection is automatic ("无感知"): when a runtime
    // is present under the scan root, scan inside containers AND enumerate local
    // images. The filesystem source self-no-ops when no runtime metadata is found, so
    // this is free on non-container hosts. `--no-container-assets` opts out;
    // `--container-asset-targets` / `--max-*` / `--no-image-assets` tune it.
    let options = if args.no_container_assets {
        ContainerScanOptions::default()
    } else {
        let mut opts = match args.container_asset_targets.as_deref() {
            Some(raw) => ContainerScanOptions::parse_targets(raw)?,
            None => ContainerScanOptions::enabled(),
        };
        opts.max_containers = args.max_containers;
        opts.include_stopped = args.include_stopped_containers;
        opts.max_images = args.max_images;
        opts.scan_images = !args.no_image_assets;
        opts
    };
    Ok(vec![Box::new(FilesystemSource::new(options))])
}

/// Detect-phase flags. HOST scans only for posture/secrets: an `--image`
/// scan_root is an assembled image rootfs, so findings would be wrongly
/// host-attributed (they anchor on `host_id`).
fn build_detect_opts(args: &ScanArgs) -> DetectOptions {
    let malware = args.malware.then(|| MalwareDetectOptions {
        workers: args.malware_jobs,
        signatures_path: args.malware_signatures.clone(),
        scan_all_dirs: args.malware_scan_deps,
    });
    let host_scan = args.image.is_none();
    DetectOptions {
        malware,
        posture: host_scan && !args.no_posture,
        secrets: host_scan && args.secrets,
    }
}

/// Run a standalone malware scan and write `malware.json` (`Vulnerability[]`)
/// into `out_dir`. `affected_asset_id` is the infected path here; the remote
/// assembler rebinds it to the host id.
fn run_static_malware(args: &ScanArgs, scan_root: &Path, out_dir: &Path) -> Result<()> {
    use agent_detect::malware::{
        detection_to_vulnerability, run_scan, MalwareOptions, SignatureSet,
    };

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
    let mut vulnerabilities: Vec<_> = result
        .detections
        .iter()
        .map(|d| detection_to_vulnerability(d, &d.path.to_string_lossy()))
        .collect();
    for vulnerability in &mut vulnerabilities {
        vulnerability.normalize_wire_fields()?;
    }

    write_json(&vulnerabilities, Some(&out_dir.join("malware.json")), true)
}

/// Serialize `value` as JSON to a file (logging `wrote <path>`) or stdout.
fn write_json<T: Serialize + ?Sized>(value: &T, dest: Option<&Path>, pretty: bool) -> Result<()> {
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

    fn asset_plan_ids(argv: &[&str]) -> Vec<&'static str> {
        let w = Wrap::try_parse_from(argv).unwrap();
        build_asset_plan(&w.args)
            .unwrap()
            .iter()
            .map(|c| c.id())
            .collect()
    }

    fn detect_flags(argv: &[&str]) -> DetectOptions {
        let w = Wrap::try_parse_from(argv).unwrap();
        build_detect_opts(&w.args)
    }

    #[test]
    fn asset_plan_excludes_detect_engines() {
        let ids = asset_plan_ids(&["x", "--malware", "--secrets"]);
        assert!(!ids.contains(&"malware"));
        assert!(!ids.contains(&"posture"));
        assert!(!ids.contains(&"secret"));
        assert_eq!(ids, vec!["filesystem"]);
    }

    #[test]
    fn posture_gated_to_host_scans() {
        assert!(detect_flags(&["x"]).posture);
        assert!(!detect_flags(&["x", "--no-posture"]).posture);
        assert!(!detect_flags(&["x", "--image", "/tmp/none.tar"]).posture);
    }

    #[test]
    fn secrets_opt_in_and_host_only() {
        assert!(!detect_flags(&["x"]).secrets);
        assert!(detect_flags(&["x", "--secrets"]).secrets);
        assert!(!detect_flags(&["x", "--secrets", "--image", "/tmp/none.tar"]).secrets);
    }

    #[test]
    fn malware_detect_opts_from_flags() {
        let d = detect_flags(&[
            "x",
            "--malware",
            "--malware-jobs",
            "4",
            "--malware-signatures",
            "/tmp/managed-signatures.json",
            "--malware-scan-deps",
        ]);
        let m = d.malware.expect("malware enabled");
        assert_eq!(m.workers, 4);
        assert_eq!(
            m.signatures_path.as_deref(),
            Some(Path::new("/tmp/managed-signatures.json"))
        );
        assert!(m.scan_all_dirs);
        assert!(detect_flags(&["x"]).malware.is_none());
    }

    #[test]
    fn static_all_writes_every_wire_asset_category_and_posture_findings() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/ssh")).unwrap();
        std::fs::write(root.path().join("etc/hostname"), "static-all\n").unwrap();
        std::fs::write(
            root.path().join("etc/os-release"),
            "ID=ubuntu\nVERSION_ID=22.04\nPRETTY_NAME=Ubuntu\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("etc/ssh/sshd_config"),
            "PermitRootLogin yes\n",
        )
        .unwrap();
        let out = tempfile::tempdir().unwrap();

        let wrapped = Wrap::try_parse_from([
            "agent-collect-host",
            "--root",
            root.path().to_str().unwrap(),
            "--target",
            "all",
            "--output",
            out.path().to_str().unwrap(),
            "--no-container-assets",
        ])
        .unwrap();
        assert!(run(wrapped.args).unwrap().is_none());

        for name in [
            "host.json",
            "packages.json",
            "services.json",
            "ports.json",
            "accounts.json",
            "credentials.json",
            "containers.json",
            "images.json",
            "findings.json",
            "detector-runs.json",
        ] {
            assert!(out.path().join(name).is_file(), "missing {name}");
        }
        assert!(!out.path().join("sbom.cyclonedx.json").exists());

        let findings: Vec<Vulnerability> =
            serde_json::from_slice(&std::fs::read(out.path().join("findings.json")).unwrap())
                .unwrap();
        assert!(findings.iter().any(|finding| finding.source == "posture"));
        let runs: Vec<DetectorRun> =
            serde_json::from_slice(&std::fs::read(out.path().join("detector-runs.json")).unwrap())
                .unwrap();
        let posture = runs
            .iter()
            .find(|run| run.detector == agent_contract::DetectorKind::Posture)
            .expect("posture run evidence");
        assert_eq!(posture.finding_count, findings.len());
    }
}
