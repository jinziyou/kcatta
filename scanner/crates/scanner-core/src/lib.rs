//! scanner-core: cyber-posture host-side scan engine.
//!
//! The library exposes a single high-level entry point [`run_scan`] that
//! orchestrates per-domain collectors and packages their findings into
//! an [`AssetReport`] conforming to the contract published by `form`.
//!
//! v0 collectors are mostly mocked; the layering is what matters here:
//! each domain (host descriptor, packages, ports, ...) is replaced
//! independently without changing the public API.

pub mod collectors;
pub mod contract;

pub use contract::{
    Account, Asset, AssetReport, Credential, CredentialKind, HostInfo, Package, Port, PortProto,
    Service, Severity, Vulnerability,
};

use chrono::Utc;
use uuid::Uuid;

/// Run a full v0 scan on the local host and return a serializable
/// [`AssetReport`].
///
/// The returned report is guaranteed to validate against
/// `form/schemas-json/AssetReport.schema.json` (enforced by the
/// `tests/contract.rs` integration test).
pub fn run_scan() -> anyhow::Result<AssetReport> {
    let host = collectors::host::collect()?;
    let host_id = host.host_id.clone();

    let mut assets = Vec::new();
    assets.extend(collectors::packages::collect(&host_id));
    assets.extend(collectors::ports::collect(&host_id));

    Ok(AssetReport {
        report_id: format!("report-{}", Uuid::new_v4()),
        collected_at: Utc::now(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        host,
        assets,
        vulnerabilities: Vec::new(),
    })
}
