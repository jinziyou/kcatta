mod accounts;
mod credentials;
mod host;
mod packages;
mod services;

pub use accounts::AccountsCollector;
pub use credentials::CredentialsCollector;
pub use host::HostCollector;
pub use packages::{collect_packages, deb_packages, DebPackage, PackagesCollector};
pub use services::ServicesCollector;

use scanner_runtime::ScanContext;

/// Asset collectors stamp `host_id` onto their assets, so the host collector
/// must have run first. Errors naming `collector` when it has not.
fn require_host_id(ctx: &ScanContext, collector: &str) -> anyhow::Result<()> {
    if ctx.host_id.is_none() {
        anyhow::bail!("host collector must run before {collector}");
    }
    Ok(())
}

pub fn collect_services(ctx: &ScanContext) -> Vec<scanner_contract::Asset> {
    services::collect(ctx)
}

pub fn collect_accounts(ctx: &ScanContext) -> Vec<scanner_contract::Asset> {
    accounts::collect(ctx)
}

pub fn collect_credentials(ctx: &ScanContext) -> Vec<scanner_contract::Asset> {
    credentials::collect(ctx)
}
