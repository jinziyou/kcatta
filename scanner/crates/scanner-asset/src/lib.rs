//! Static filesystem asset discovery for cyber-posture.
//!
//! Reads a **mounted directory** (disk image, chroot, or `/`) and produces
//! either per-category JSON files or [`scanner_contract::Asset`] batches via
//! the [`Collector`] trait.
//!
//! # Outputs
//!
//! | Mode | API | Result |
//! | --- | --- | --- |
//! | Standalone CLI | [`run_static_scan`] | `host.json`, `packages.json`, … |
//! | Runtime plan | [`default_collectors`] + [`scanner_runtime::run_scan_at`] | merged [`scanner_contract::AssetReport`] |
//!
//! # Collectors
//!
//! Host → Packages → Services → Accounts → Credentials. Packages cover dpkg,
//! apk, rpm, PyPI, and npm with OSV `ecosystem` tags for form-side CVE matching.
//!
//! See the [crate README](../README.md) and [workspace docs](../../docs/ARCHITECTURE.md).

mod collectors;
mod discover;
mod root;
mod sbom;
mod scan;

pub use collectors::{
    AccountsCollector, CredentialsCollector, HostCollector, PackagesCollector, ServicesCollector,
};
pub use discover::discover_project_roots;
pub use sbom::{build_sbom, build_sbom_from_assets, Bom};
pub use scan::{run_static_scan, ScanOptions, ScanOutput, ScanTarget};

use scanner_runtime::Collector;

/// Default v0 collector plan: host, packages, services, accounts, credentials.
///
/// Pass to [`scanner_runtime::run_scan_at`] or [`scanner_runtime::run_scan_at_with`].
pub fn default_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(HostCollector),
        Box::new(PackagesCollector),
        Box::new(ServicesCollector),
        Box::new(AccountsCollector),
        Box::new(CredentialsCollector),
    ]
}
