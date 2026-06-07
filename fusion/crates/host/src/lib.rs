//! posture host detection: static asset discovery + scan orchestration.
//!
//! Reads a **mounted directory** (disk image, chroot, `/`, or a Windows volume)
//! and produces either per-category JSON files or [`fusion_contract::Asset`]
//! batches via the [`Collector`] trait. Also owns the host-domain scheduling
//! primitives — the [`Collector`] plugin interface, [`ScanContext`], and
//! [`run_scan_at`] — that the `fusion` orchestration binary drives.
//!
//! # Outputs
//!
//! | Mode | API | Result |
//! | --- | --- | --- |
//! | Per-asset JSON | [`run_static_scan`] | `host.json`, `packages.json`, … |
//! | Merged report | [`default_collectors`] + [`run_scan_at`] | merged [`fusion_contract::AssetReport`] |
//!
//! # Collectors
//!
//! Host → Packages → Services → Accounts → Credentials. Linux packages cover dpkg,
//! apk, rpm, PyPI, and npm; Windows adds registry Uninstall inventory plus PyPI/npm
//! under `Program Files` / user profiles. OSV `ecosystem` tags feed form-side CVE matching.
//! With the `malware` feature, [`MalwareCollector`] adds ClamAV `INSTREAM` findings.
//!
//! # Internal layout
//!
//! - [`collector`] — the [`Collector`] trait, [`ScanContext`], [`CollectorOutput`]
//! - `scan_runner` — [`run_scan_at`] et al. (assemble collectors → `AssetReport`)
//! - [`platform`] — OS detection and Windows registry backends
//! - `sources/` — fixed-path readers (FHS files, package DBs)
//! - `walk/` — bounded directory walks with pattern handlers (PyPI, npm, SSH homes)
//! - `collectors/` — semantic [`Collector`] facades that dispatch by OS and merge outputs
//! - `malware/` (feature `malware`) — ClamAV INSTREAM scanning
//!
//! See the [crate README](../README.md) and [workspace docs](../../../docs/ARCHITECTURE.md).

mod collector;
mod collectors;
pub mod platform;
mod root;
mod sbom;
mod scan;
mod scan_runner;
mod sources;
mod walk;

#[cfg(feature = "malware")]
pub mod malware;

pub use collector::{Collector, CollectorOutput, ScanContext, WindowsPackageProfile};
pub use collectors::{
    AccountsCollector, CredentialsCollector, HostCollector, PackagesCollector, ServicesCollector,
};
pub use sbom::{build_sbom, build_sbom_from_assets, Bom};
pub use scan::{run_static_scan, ScanOptions, ScanOutput, ScanTarget};
pub use scan_runner::{run_scan, run_scan_at, run_scan_at_with, run_scan_at_with_opts};
pub use sources::packages::{deb_packages, DebPackage};
pub use walk::discover_project_roots;

#[cfg(feature = "malware")]
pub use malware::{default_workers, MalwareCollector};

/// Default v0 collector plan: host, packages, services, accounts, credentials.
///
/// Pass to [`run_scan_at`] or [`run_scan_at_with`].
pub fn default_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(HostCollector),
        Box::new(PackagesCollector),
        Box::new(ServicesCollector),
        Box::new(AccountsCollector),
        Box::new(CredentialsCollector),
    ]
}
