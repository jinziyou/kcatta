//! Fixed-path and walk-assisted package inventory sources.

pub mod apk;
pub mod dpkg;
pub mod npm;
pub mod pypi;
pub mod rpm;

pub use dpkg::{deb_packages, DebPackage};

use probe_runtime::ScanContext;

/// PyPI and npm packages (shared by Linux and Windows inventory).
pub fn collect_language_packages(ctx: &ScanContext) -> Vec<probe_contract::Asset> {
    let mut assets = pypi::collect(ctx);
    assets.extend(npm::collect(ctx));
    assets
}
