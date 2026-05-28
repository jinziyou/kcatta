//! scanner-runtime: orchestrates domain collectors into an [`AssetReport`].
//!
//! Domain logic lives in separate workspace members (`scanner-asset`,
//! `scanner-vuln`, ...). This crate only defines the [`Collector`] trait,
//! [`ScanContext`], and [`run_scan`].

mod collector;

pub use collector::{Collector, CollectorOutput, ScanContext};
pub use scanner_contract::{
    Account, Asset, AssetReport, Credential, CredentialKind, HostInfo, Package, Port,
    PortProto, Service, Severity, Vulnerability,
};

use chrono::Utc;
use uuid::Uuid;

/// Run collectors in order, merge their output into one [`AssetReport`].
///
/// Callers must include a host collector first (e.g. `scanner_asset::HostCollector`)
/// so asset collectors receive a `host_id` in [`ScanContext`].
pub fn run_scan(collectors: &[Box<dyn Collector>]) -> anyhow::Result<AssetReport> {
    let mut ctx = ScanContext::default();
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
