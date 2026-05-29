//! scanner-asset: static filesystem asset discovery.
//!
//! Scans a **mounted directory** (disk image, chroot, or `/`) and writes
//! per-category JSON files (`host.json`, `packages.json`).

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

/// Collectors for a full [`scanner_runtime::run_scan_at`] plan.
pub fn default_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(HostCollector),
        Box::new(PackagesCollector),
        Box::new(ServicesCollector),
        Box::new(AccountsCollector),
        Box::new(CredentialsCollector),
    ]
}
