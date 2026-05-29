//! Installed package collectors.
//!
//! Combines OS packages (dpkg) with language ecosystems (PyPI, npm). Each
//! collector tags its assets with an OSV `ecosystem` so `form` can match a
//! single host's mixed inventory against the right advisory databases.

mod dpkg;
mod npm;
mod pypi;

pub use dpkg::{deb_packages, DebPackage};

use scanner_runtime::{Collector, CollectorOutput, ScanContext};

pub struct PackagesCollector;

impl Collector for PackagesCollector {
    fn id(&self) -> &'static str {
        "packages"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        require_host_id(ctx)?;
        let mut assets = dpkg::collect(ctx);
        assets.extend(pypi::collect(ctx));
        assets.extend(npm::collect(ctx));
        Ok(CollectorOutput::Assets(assets))
    }
}

fn require_host_id(ctx: &ScanContext) -> anyhow::Result<()> {
    if ctx.host_id.is_none() {
        anyhow::bail!("host collector must run before packages");
    }
    Ok(())
}
