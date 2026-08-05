//! Compatibility collector facades for static filesystem scans.
//!
//! Each collector implements the legacy, single-result [`crate::Collector`]
//! trait or exposes a `collect` function used by
//! [`crate::scan::run_static_scan`]. A blanket adapter also makes every
//! collector usable through the multi-result [`crate::Source`] interface.
//! The host collector must run first so subsequent collectors can stamp
//! `host_id` onto assets.

mod accounts;
mod containers;
mod credentials;
mod host;
mod images;
mod nested;
pub(crate) mod packages;
mod ports;
mod services;
mod stamp;

pub use accounts::AccountsCollector;
#[allow(unused_imports)] // Compatibility facade retained for crate-local callers.
pub(crate) use containers::collect as collect_containers;
pub(crate) use containers::collect_with_coverage as collect_containers_with_coverage;
pub(crate) use containers::ContainerCoverage;
pub use containers::ContainersCollector;
pub use credentials::CredentialsCollector;
pub(crate) use host::collect_host;
pub use host::HostCollector;
pub(crate) use images::collect as collect_images;
pub use images::ImagesCollector;
pub(crate) use nested::collect as collect_nested_assets;
pub use nested::NestedAssetsCollector;
pub(crate) use packages::collect_packages_with_coverage;
pub use packages::{collect_packages, PackagesCollector};
pub use ports::PortsCollector;
pub use services::ServicesCollector;
pub(crate) use stamp::stamp_nested_assets;

use crate::ScanContext;

/// Asset collectors stamp `host_id` onto their assets, so the host collector
/// must have run first. Errors naming `collector` when it has not.
fn require_host_id(ctx: &ScanContext, collector: &str) -> anyhow::Result<()> {
    if ctx.host_id.is_none() {
        anyhow::bail!("host collector must run before {collector}");
    }
    Ok(())
}

/// Collect service assets discovered under `ctx.scan_root`.
pub fn collect_services(ctx: &ScanContext) -> Vec<agent_contract::Asset> {
    services::collect(ctx)
}

/// Collect services with same-pass source diagnostics.
pub(crate) fn collect_services_with_coverage(
    ctx: &ScanContext,
) -> (
    Vec<agent_contract::Asset>,
    crate::sources::services::ServiceCoverage,
) {
    services::collect_with_coverage(ctx)
}

/// Collect local account assets discovered under `ctx.scan_root`.
pub fn collect_accounts(ctx: &ScanContext) -> Vec<agent_contract::Asset> {
    accounts::collect(ctx)
}

/// Collect local accounts with same-pass source diagnostics.
pub(crate) fn collect_accounts_with_coverage(
    ctx: &ScanContext,
) -> (
    Vec<agent_contract::Asset>,
    crate::sources::accounts::AccountCoverage,
) {
    accounts::collect_with_coverage(ctx)
}

/// Collect credential assets discovered under `ctx.scan_root`.
pub fn collect_credentials(ctx: &ScanContext) -> Vec<agent_contract::Asset> {
    credentials::collect(ctx)
}

/// Collect credentials with same-pass source diagnostics.
pub(crate) fn collect_credentials_with_coverage(
    ctx: &ScanContext,
) -> (
    Vec<agent_contract::Asset>,
    crate::sources::credentials::CredentialCoverage,
) {
    credentials::collect_with_coverage(ctx)
}
