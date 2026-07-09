//! Asset collectors for static filesystem scans.
//!
//! Each collector implements [`crate::Collector`] or exposes a
//! `collect` function used by [`crate::scan::run_static_scan`].
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
pub use containers::ContainersCollector;
pub use credentials::CredentialsCollector;
pub use host::HostCollector;
pub use images::ImagesCollector;
pub use nested::NestedAssetsCollector;
pub use packages::{collect_packages, DebPackage, PackagesCollector};
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

/// Collect local account assets discovered under `ctx.scan_root`.
pub fn collect_accounts(ctx: &ScanContext) -> Vec<agent_contract::Asset> {
    accounts::collect(ctx)
}

/// Collect credential assets discovered under `ctx.scan_root`.
pub fn collect_credentials(ctx: &ScanContext) -> Vec<agent_contract::Asset> {
    credentials::collect(ctx)
}
