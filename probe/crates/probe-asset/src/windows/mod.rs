//! Windows host asset collectors (offline registry hives and live registry on Windows).

mod accounts;
mod boot;
mod distro;
mod host;
mod network;
mod packages;
mod paths;
mod registry;
mod services;
mod store;

pub use accounts::collect_accounts;
pub use distro::WindowsDistro;
pub use host::collect_host;
pub use packages::collect_packages;
pub use paths::{first_existing_dir, users_dir};
pub use registry::RegistryAccess;
pub use services::collect_services;
