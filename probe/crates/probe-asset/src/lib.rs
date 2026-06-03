//! Static filesystem asset discovery for cyber-posture.
//!
//! Reads a **mounted directory** (disk image, chroot, `/`, or a Windows volume)
//! and produces either per-category JSON files or [`probe_contract::Asset`] batches via
//! the [`Collector`] trait.
//!
//! # Outputs
//!
//! | Mode | API | Result |
//! | --- | --- | --- |
//! | Standalone CLI | [`run_static_scan`] | `host.json`, `packages.json`, … |
//! | Runtime plan | [`default_collectors`] + [`probe_runtime::run_scan_at`] | merged [`probe_contract::AssetReport`] |
//!
//! # Collectors
//!
//! Host → Packages → Services → Accounts → Credentials. Linux packages cover dpkg,
//! apk, rpm, PyPI, and npm; Windows adds registry Uninstall inventory plus PyPI/npm
//! under `Program Files` / user profiles. OSV `ecosystem` tags feed form-side CVE matching.
//!
//! # Internal layout
//!
//! - [`platform`] — OS detection and Windows registry backends
//! - `sources/` — fixed-path readers (FHS files, package DBs)
//! - `walk/` — bounded directory walks with pattern handlers (PyPI, npm, SSH homes)
//! - `collectors/` — semantic [`Collector`] facades that dispatch by OS and merge outputs
//!
//! See the [crate README](../README.md) and [workspace docs](../../docs/ARCHITECTURE.md).

mod collectors;
pub mod platform;
mod root;
mod sbom;
mod scan;
mod sources;
mod walk;

pub use collectors::{
    AccountsCollector, CredentialsCollector, HostCollector, PackagesCollector, ServicesCollector,
};
pub use sbom::{build_sbom, build_sbom_from_assets, Bom};
pub use scan::{run_static_scan, ScanOptions, ScanOutput, ScanTarget};
pub use sources::packages::{deb_packages, DebPackage};
pub use walk::discover_project_roots;

use probe_runtime::Collector;

/// Default v0 collector plan: host, packages, services, accounts, credentials.
///
/// Pass to [`probe_runtime::run_scan_at`] or [`probe_runtime::run_scan_at_with`].
pub fn default_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(HostCollector),
        Box::new(PackagesCollector),
        Box::new(ServicesCollector),
        Box::new(AccountsCollector),
        Box::new(CredentialsCollector),
    ]
}
