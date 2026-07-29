//! Scan orchestration: assemble inventory [`Source`](crate::Source)s into an [`AssetReport`].
//!
//! ## Two scan APIs (intentional)
//!
//! | API | Module | Output | Used by |
//! | --- | --- | --- | --- |
//! | [`run_scan_at`] | this module | merged asset-only [`AssetReport`] | `agentd run`, composition code |
//! | [`run_scan_with_detect`] | this module | merged assets + findings [`AssetReport`] | compatibility callers, merged CLI |
//! | [`crate::run_static_scan`] | [`crate::scan`] | per-file JSON (`-o DIR`) | static CLI / Form deploy pull |
//!
//! Both accept either multi-result sources or legacy single-result collectors;
//! keep both until a single facade can preserve
//! the two output shapes without breaking deploy consumers.
//!
//! **Collect vs detect**: [`run_scan_at`] runs inventory sources only. New
//! composition code should pass its report host id to `agent_detect::host` and
//! merge the returned findings. [`run_scan_with_detect`] preserves the former
//! collect-then-detect convenience API without making detection a collector.
//!
//! # Example
//!
//! ```no_run
//! use agent_collect_host::{default_sources, run_scan_at};
//!
//! let report = run_scan_at(&default_sources(), "/")?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use agent_contract::AssetReport;
use anyhow::Context as _;
use chrono::Utc;
use uuid::Uuid;

use crate::collector::{ScanContext, Source, SourceResult, WindowsPackageProfile};
use crate::detect_phase::{run_detect_at, DetectOpts};

/// Run sources (or legacy collectors) at the live host root (`/`).
pub fn run_scan<S>(sources: &[Box<S>]) -> anyhow::Result<AssetReport>
where
    S: Source + ?Sized,
{
    run_scan_at(sources, "/")
}

/// Run sources against `scan_root` (mounted filesystem or `/`).
///
/// The plan must emit one host result before any later source that requires a
/// `host_id` in [`ScanContext`].
pub fn run_scan_at<S>(
    sources: &[Box<S>],
    scan_root: impl AsRef<std::path::Path>,
) -> anyhow::Result<AssetReport>
where
    S: Source + ?Sized,
{
    run_scan_at_with(sources, scan_root, Vec::new())
}

/// Like [`run_scan_at`], but also passes extra project roots (relative to
/// `scan_root`) for language-package collectors to scan.
pub fn run_scan_at_with<S>(
    sources: &[Box<S>],
    scan_root: impl AsRef<std::path::Path>,
    project_roots: Vec<std::path::PathBuf>,
) -> anyhow::Result<AssetReport>
where
    S: Source + ?Sized,
{
    run_scan_at_with_opts(
        sources,
        scan_root,
        project_roots,
        WindowsPackageProfile::default(),
        true,
    )
}

/// Like [`run_scan_at_with`], but also sets the Windows package collection scope.
pub fn run_scan_at_with_opts<S>(
    sources: &[Box<S>],
    scan_root: impl AsRef<std::path::Path>,
    project_roots: Vec<std::path::PathBuf>,
    windows_packages: WindowsPackageProfile,
    project_discovery: bool,
) -> anyhow::Result<AssetReport>
where
    S: Source + ?Sized,
{
    let mut ctx = ScanContext::at(scan_root)
        .with_project_roots(project_roots)
        .with_project_discovery(project_discovery)
        .with_windows_packages(windows_packages);
    let mut host = None;
    let mut assets = Vec::new();

    for source in sources {
        let source_id = Source::id(&**source);
        let results = Source::collect(&**source, &mut ctx)
            .with_context(|| format!("collecting inventory source {source_id}"))?;
        for result in results {
            match result {
                SourceResult::Host(emitted_host) => {
                    if host.is_some() {
                        anyhow::bail!(
                            "inventory source {source_id} emitted a second host; a scan plan must emit exactly one host"
                        );
                    }
                    ctx.host_id = Some(emitted_host.host_id.clone());
                    ctx.host = Some(emitted_host.clone());
                    host = Some(emitted_host);
                }
                SourceResult::Assets(batch) => {
                    if host.is_none() {
                        anyhow::bail!(
                            "inventory source {source_id} emitted assets before the host"
                        );
                    }
                    assets.extend(batch);
                }
            }
        }
    }

    let host =
        host.ok_or_else(|| anyhow::anyhow!("scan plan must include a source that emits a host"))?;

    let mut report = AssetReport {
        report_id: format!("report-{}", Uuid::new_v4()),
        collected_at: Utc::now(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        source_agent_id: None,
        source_target_id: None,
        host,
        assets,
        vulnerabilities: Vec::new(),
        detector_runs: None,
    };
    report.normalize_wire_fields()?;
    Ok(report)
}

/// Backward-compatible asset collect then optional detect-phase facade.
///
/// `detect` may be empty ([`DetectOpts::default`]) for assets-only.
pub fn run_scan_with_detect<S>(
    sources: &[Box<S>],
    scan_root: impl AsRef<std::path::Path>,
    project_roots: Vec<std::path::PathBuf>,
    windows_packages: WindowsPackageProfile,
    detect: &DetectOpts,
) -> anyhow::Result<AssetReport>
where
    S: Source + ?Sized,
{
    let scan_root = scan_root.as_ref();
    let mut report =
        run_scan_at_with_opts(sources, scan_root, project_roots, windows_packages, true)?;
    if detect.any_enabled() {
        let findings = run_detect_at(scan_root, &report.host.host_id, detect)?;
        report.detector_runs = Some(agent_detect::host::completed_runs(detect, &findings));
        report.vulnerabilities.extend(findings);
    } else {
        report.detector_runs = Some(Vec::new());
    }
    report.normalize_wire_fields()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use agent_contract::{Asset, HostInfo, Package, Service};

    use super::*;
    use crate::{Collector, CollectorOutput};

    fn fake_host(host_id: &str) -> HostInfo {
        HostInfo {
            host_id: host_id.into(),
            hostname: "fake".into(),
            os: "Test OS".into(),
            kernel: None,
            arch: None,
            ip_addrs: Vec::new(),
            mac_addrs: Vec::new(),
            boot_time: None,
        }
    }

    struct FakeSource;

    impl Source for FakeSource {
        fn id(&self) -> &'static str {
            "fake"
        }

        fn collect(&self, _ctx: &mut ScanContext) -> anyhow::Result<Vec<SourceResult>> {
            Ok(vec![
                SourceResult::Host(fake_host("host-fake")),
                SourceResult::Assets(vec![Asset::Package(Package {
                    asset_id: "pkg-one".into(),
                    parent_asset_id: None,
                    name: "one".into(),
                    version: "1".into(),
                    source: Some("fake".into()),
                    source_name: None,
                    source_version: None,
                    install_path: None,
                    ecosystem: None,
                })]),
                SourceResult::Assets(vec![Asset::Service(Service {
                    asset_id: "svc-two".into(),
                    parent_asset_id: None,
                    name: "two".into(),
                    status: "running".into(),
                    exec_path: None,
                })]),
            ])
        }
    }

    #[test]
    fn flattens_multiple_results_from_one_source() {
        let sources: Vec<Box<dyn Source>> = vec![Box::new(FakeSource)];
        let report = run_scan_at(&sources, "/unused").unwrap();

        assert_eq!(report.host.host_id, "host-fake");
        assert_eq!(report.assets.len(), 2);
        assert!(matches!(report.assets[0], Asset::Package(_)));
        assert!(matches!(report.assets[1], Asset::Service(_)));
    }

    struct LegacyHostCollector;

    impl Collector for LegacyHostCollector {
        fn id(&self) -> &'static str {
            "legacy-host"
        }

        fn collect(&self, _ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
            Ok(CollectorOutput::Host(fake_host("host-legacy")))
        }
    }

    #[test]
    fn accepts_legacy_single_result_collector_plan() {
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(LegacyHostCollector)];
        let report = run_scan_at(&collectors, "/unused").unwrap();

        assert_eq!(report.host.host_id, "host-legacy");
    }

    struct AssetsBeforeHostSource;

    impl Source for AssetsBeforeHostSource {
        fn id(&self) -> &'static str {
            "assets-first"
        }

        fn collect(&self, _ctx: &mut ScanContext) -> anyhow::Result<Vec<SourceResult>> {
            Ok(vec![
                SourceResult::Assets(Vec::new()),
                SourceResult::Host(fake_host("host-too-late")),
            ])
        }
    }

    #[test]
    fn rejects_assets_before_host_even_when_batch_is_empty() {
        let sources: Vec<Box<dyn Source>> = vec![Box::new(AssetsBeforeHostSource)];
        let error = run_scan_at(&sources, "/unused").unwrap_err().to_string();

        assert!(error.contains("assets-first emitted assets before the host"));
    }

    struct DuplicateHostSource;

    impl Source for DuplicateHostSource {
        fn id(&self) -> &'static str {
            "duplicate-host"
        }

        fn collect(&self, _ctx: &mut ScanContext) -> anyhow::Result<Vec<SourceResult>> {
            Ok(vec![
                SourceResult::Host(fake_host("host-one")),
                SourceResult::Host(fake_host("host-two")),
            ])
        }
    }

    #[test]
    fn rejects_a_second_host_result() {
        let sources: Vec<Box<dyn Source>> = vec![Box::new(DuplicateHostSource)];
        let error = run_scan_at(&sources, "/unused").unwrap_err().to_string();

        assert!(error.contains("duplicate-host emitted a second host"));
    }
}
