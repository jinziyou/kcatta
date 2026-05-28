//! scanner-core: backward-compatible facade over the split workspace crates.
//!
//! New code should depend on `scanner-runtime` + domain crates directly.
//! This crate re-exports the contract and provides [`run_scan`] with the
//! default v0 asset discovery plan.

pub use scanner_contract as contract;
pub use scanner_runtime::{
    run_scan as run_scan_plan, Account, Asset, AssetReport, Collector, CollectorOutput,
    Credential, CredentialKind, HostInfo, Package, Port, PortProto, ScanContext, Service,
    Severity, Vulnerability,
};

/// Run the default v0 scan (host + packages).
pub fn run_scan() -> anyhow::Result<AssetReport> {
    run_scan_plan(&scanner_asset::default_collectors())
}

/// Run scan against a mounted root (static filesystem layout).
pub fn run_scan_at(scan_root: impl AsRef<std::path::Path>) -> anyhow::Result<AssetReport> {
    scanner_runtime::run_scan_at(&scanner_asset::default_collectors(), scan_root)
}
