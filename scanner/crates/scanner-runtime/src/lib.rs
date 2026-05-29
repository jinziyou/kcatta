//! scanner-runtime: orchestrates domain collectors into an [`AssetReport`].
//!
//! Domain logic lives in separate workspace members (`scanner-asset`,
//! `scanner-malware`, ...). This crate only defines the [`Collector`] trait,
//! [`ScanContext`], and [`run_scan`].

mod collector;

pub use collector::{Collector, CollectorOutput, ScanContext};
pub use scanner_contract::{
    Account, Asset, AssetReport, Credential, CredentialKind, HostInfo, Package, Port,
    PortProto, Service, Severity, Vulnerability,
};

use chrono::Utc;
use uuid::Uuid;

/// Run collectors at the live host root (`/`).
pub fn run_scan(collectors: &[Box<dyn Collector>]) -> anyhow::Result<AssetReport> {
    run_scan_at(collectors, "/")
}

/// Run collectors against `scan_root` (mounted filesystem or `/`).
///
/// Callers must include a host collector first so asset collectors receive
/// `host_id` in [`ScanContext`].
pub fn run_scan_at(
    collectors: &[Box<dyn Collector>],
    scan_root: impl AsRef<std::path::Path>,
) -> anyhow::Result<AssetReport> {
    run_scan_at_with(collectors, scan_root, Vec::new())
}

/// Like [`run_scan_at`], but also passes extra project roots (relative to
/// `scan_root`) for language-package collectors to scan.
pub fn run_scan_at_with(
    collectors: &[Box<dyn Collector>],
    scan_root: impl AsRef<std::path::Path>,
    project_roots: Vec<std::path::PathBuf>,
) -> anyhow::Result<AssetReport> {
    let mut ctx = ScanContext::at(scan_root).with_project_roots(project_roots);
    let mut assets = Vec::new();
    let mut vulnerabilities = Vec::new();

    for collector in collectors {
        match collector.collect(&mut ctx)? {
            CollectorOutput::Host(host) => {
                ctx.host_id = Some(host.host_id.clone());
                ctx.host = Some(host);
            }
            CollectorOutput::Assets(batch) => assets.extend(batch),
            CollectorOutput::Vulnerabilities(batch) => vulnerabilities.extend(batch),
        }
    }

    let host = ctx
        .host
        .ok_or_else(|| anyhow::anyhow!("scan plan must include a host collector"))?;

    Ok(AssetReport {
        report_id: format!("report-{}", Uuid::new_v4()),
        collected_at: Utc::now(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        host,
        assets,
        vulnerabilities,
    })
}
