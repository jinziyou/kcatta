//! Listening-port collectors.

mod proc_net;

use scanner_runtime::{Collector, CollectorOutput, ScanContext};

pub struct PortsCollector;

impl Collector for PortsCollector {
    fn id(&self) -> &'static str {
        "ports"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        require_host_id(ctx)?;
        Ok(CollectorOutput::Assets(proc_net::collect()))
    }
}

fn require_host_id(ctx: &ScanContext) -> anyhow::Result<()> {
    if ctx.host_id.is_none() {
        anyhow::bail!("host collector must run before ports");
    }
    Ok(())
}
