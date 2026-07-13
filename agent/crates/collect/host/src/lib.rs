//! kcatta host **collect**: static asset discovery + scan orchestration.
//!
//! Reads a **mounted directory** (disk image, chroot, `/`, or a Windows volume)
//! and produces [`agent_contract::Asset`] batches. [`Source`] is the
//! source-oriented, multi-result interface; the original single-result
//! [`Collector`] interface remains available for compatibility.
//! Detect engines (malware / posture / secrets) are owned by
//! `agent_detect::host`; [`detect_phase`] keeps the former collect-host API as a
//! compatibility facade. Detection findings are not assets or collectors.
//!
//! # Outputs
//!
//! | Mode | API | Result |
//! | --- | --- | --- |
//! | Per-asset JSON | [`run_static_scan`] | `host.json`, `packages.json`, … |
//! | Merged report | [`default_collectors`] + [`run_scan_at`] (+ optional [`run_detect_at`]) | [`agent_contract::AssetReport`] |
//!
//! # Collectors (assets only)
//!
//! Host → Packages → Services → Ports → Accounts → Credentials → Containers.
//! Linux packages cover dpkg, apk, rpm, PyPI, and npm; Windows adds registry
//! Uninstall inventory plus PyPI/npm. OSV `ecosystem` tags feed analyzer-side CVE matching.
//!
//! # Internal layout
//!
//! - [`collector`] — [`Source`], [`Collector`], their result types, and [`ScanContext`]
//! - `scan_runner` — [`run_scan_at`] et al. (sources or legacy collectors → `AssetReport`)
//! - [`detect_phase`] — compatibility aliases for `agent_detect::host`
//! - [`platform`] — OS detection and Windows registry backends
//! - `sources/` — fixed-path readers (FHS files, package DBs)
//! - `walk/` — bounded directory walks with pattern handlers (PyPI, npm, SSH homes)
//! - `collectors/` — legacy category-oriented [`Collector`] facades
//!
//! See the [crate README](../README.md) and [workspace docs](../../../../docs/ARCHITECTURE.md).

pub mod cli;
mod collector;
mod collectors;
mod container_scan;
pub mod detect_phase;
pub mod image;
pub mod platform;
mod root;
mod sbom;
mod scan;
mod scan_runner;
pub mod sources;
mod walk;

pub use collector::{
    Collector, CollectorOutput, ScanContext, Source, SourceResult, WindowsPackageProfile,
};
pub use collectors::{
    AccountsCollector, ContainersCollector, CredentialsCollector, HostCollector, ImagesCollector,
    NestedAssetsCollector, PackagesCollector, PortsCollector, ServicesCollector,
};
pub use container_scan::ContainerScanOptions;
pub use detect_phase::{run_detect_at, DetectOpts, MalwareDetectOpts};
pub use image::{assemble_image_rootfs, assemble_rootfs_from_layer_dirs};
pub use sbom::{build_sbom, build_sbom_from_assets, Bom};
pub use scan::{run_static_scan, ScanOptions, ScanOutput, ScanTarget};
pub use scan_runner::{
    run_scan, run_scan_at, run_scan_at_with, run_scan_at_with_opts, run_scan_with_detect,
};
pub use sources::{
    packages::{deb_packages, DebPackage},
    FilesystemSource,
};
pub use walk::discover_project_roots;

/// Default inventory-source plan.
///
/// The default groups all filesystem-backed categories under one
/// [`FilesystemSource`]. Malware / posture / secrets remain detect-phase
/// options passed to [`run_scan_with_detect`] or [`run_detect_at`].
pub fn default_sources() -> Vec<Box<dyn Source>> {
    vec![Box::new(FilesystemSource::default())]
}

/// Default legacy collector plan: host, packages, services, ports, accounts,
/// credentials, and containers.
///
/// This intentionally preserves the original seven-step category plan for
/// callers that depend on collector identities or invoke collectors directly.
/// New source-oriented code should prefer [`default_sources`].
pub fn default_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(HostCollector),
        Box::new(PackagesCollector),
        Box::new(ServicesCollector),
        Box::new(PortsCollector),
        Box::new(AccountsCollector),
        Box::new(CredentialsCollector),
        Box::new(ContainersCollector),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_plans_keep_source_and_legacy_shapes() {
        assert_eq!(default_sources().len(), 1);
        assert_eq!(Source::id(&*default_sources()[0]), "filesystem");

        let collectors = default_collectors();
        let ids: Vec<_> = collectors
            .iter()
            .map(|collector| Collector::id(&**collector))
            .collect();
        assert_eq!(
            ids,
            [
                "host",
                "packages",
                "services",
                "ports",
                "accounts",
                "credentials",
                "containers"
            ]
        );
    }
}
