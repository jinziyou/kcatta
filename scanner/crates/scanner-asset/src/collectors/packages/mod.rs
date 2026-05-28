//! Installed package collectors.

mod dpkg;

use scanner_runtime::{Collector, CollectorOutput, ScanContext};

pub struct PackagesCollector;

impl Collector for PackagesCollector {
    fn id(&self) -> &'static str {
        "packages"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        require_host_id(ctx)?;
        Ok(CollectorOutput::Assets(dpkg::collect(ctx)))
    }
}

fn require_host_id(ctx: &ScanContext) -> anyhow::Result<()> {
    if ctx.host_id.is_none() {
        anyhow::bail!("host collector must run before packages");
    }
    Ok(())
}
