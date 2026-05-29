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

pub fn collect_services(ctx: &ScanContext) -> Vec<scanner_contract::Asset> {
    services::collect(ctx)
}

pub fn collect_accounts(ctx: &ScanContext) -> Vec<scanner_contract::Asset> {
    accounts::collect(ctx)
}

pub fn collect_credentials(ctx: &ScanContext) -> Vec<scanner_contract::Asset> {
    credentials::collect(ctx)
}
