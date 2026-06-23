//! Listening-port collector (Linux `/proc/net`).

use crate::sources;
use crate::{Collector, CollectorOutput, ScanContext};
use agent_contract::Asset;

/// Collects listening TCP/UDP ports (the host's network attack surface) from
/// `/proc/net` under `ctx.scan_root`. Yields nothing for image / chroot scans
/// whose `proc/` is empty, so a listener is never mis-attributed.
pub struct PortsCollector;

impl Collector for PortsCollector {
    fn id(&self) -> &'static str {
        "ports"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "ports")?;
        Ok(CollectorOutput::Assets(collect(ctx)))
    }
}

/// Listening ports as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    sources::ports::collect(ctx)
}
