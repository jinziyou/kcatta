//! kcatta host **collect**: static asset discovery + scan orchestration.
//!
//! Reads a **mounted directory** (disk image, chroot, `/`, or a Windows volume)
//! and produces [`agent_contract::Asset`] batches via the [`Collector`] trait.
//! Detect engines (malware / posture / secrets) run in a **separate phase**
//! ([`detect_phase`]) and merge findings into the report — they are not asset
//! collectors.
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
//! - [`collector`] — the [`Collector`] trait, [`ScanContext`], [`CollectorOutput`]
//! - `scan_runner` — [`run_scan_at`] et al. (asset collectors → `AssetReport`)
//! - [`detect_phase`] — malware / posture / secrets → `Vulnerability` (orchestration)
//! - [`platform`] — OS detection and Windows registry backends
//! - `sources/` — fixed-path readers (FHS files, package DBs)
//! - `walk/` — bounded directory walks with pattern handlers (PyPI, npm, SSH homes)
//! - `collectors/` — asset [`Collector`] facades
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
mod sources;
mod walk;

pub use collector::{Collector, CollectorOutput, ScanContext, WindowsPackageProfile};
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
pub use sources::packages::{deb_packages, DebPackage};
pub use walk::discover_project_roots;

/// Default **asset** collector plan: host, packages, services, ports, accounts,
/// credentials, containers.
///
/// Does **not** include malware / posture / secrets — those are detect-phase
/// options passed to [`run_scan_with_detect`] or [`run_detect_at`].
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
