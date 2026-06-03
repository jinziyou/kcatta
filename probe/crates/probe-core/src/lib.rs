//! probe-core: backward-compatible facade over the split workspace crates.
//!
//! New code should depend on `probe-runtime` + domain crates directly.
//! This crate re-exports the contract and provides [`run_scan`] with the
//! default v0 asset discovery plan.
//!
//! # Example
//!
//! ```no_run
//! use probe_core::run_scan_at;
//!
//! let report = run_scan_at("/mnt/image")?;
//! # Ok::<(), anyhow::Error>(())
//! ```

pub use probe_contract as contract;
pub use probe_runtime::{
    run_scan as run_scan_plan, Account, Asset, AssetReport, Collector, CollectorOutput, Credential,
    CredentialKind, HostInfo, Package, Port, PortProto, ScanContext, Service, Severity,
    Vulnerability,
};

/// Run the default v0 scan (host + packages).
pub fn run_scan() -> anyhow::Result<AssetReport> {
    run_scan_plan(&probe_asset::default_collectors())
}

/// Run scan against a mounted root (static filesystem layout).
pub fn run_scan_at(scan_root: impl AsRef<std::path::Path>) -> anyhow::Result<AssetReport> {
    probe_runtime::run_scan_at(&probe_asset::default_collectors(), scan_root)
}
