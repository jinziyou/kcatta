//! scanner-asset: static filesystem asset discovery.
//!
//! Scans a **mounted directory** (disk image, chroot, or `/`) and writes
//! per-category JSON files (`host.json`, `packages.json`, `ports.json`).

mod collectors;
mod root;
mod scan;

pub use collectors::{HostCollector, PackagesCollector, PortsCollector};
pub use scan::{run_static_scan, ScanOptions, ScanOutput, ScanTarget};

use scanner_runtime::Collector;

/// Collectors for a full [`scanner_runtime::run_scan_at`] plan (all asset types).
pub fn default_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(HostCollector),
        Box::new(PackagesCollector),
        Box::new(PortsCollector),
    ]
}
