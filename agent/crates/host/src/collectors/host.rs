//! Host descriptor collector (dispatches to fixed-path sources or Windows registry).

use crate::{Collector, CollectorOutput, ScanContext};
use agent_contract::HostInfo;

use crate::platform::{self, OsFamily};
use crate::sources;

/// Collects [`HostInfo`] from static files or the Windows registry.
pub struct HostCollector;

impl Collector for HostCollector {
    fn id(&self) -> &'static str {
        "host"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        Ok(CollectorOutput::Host(collect_host(ctx)?))
    }
}

pub(crate) fn collect_host(ctx: &ScanContext) -> anyhow::Result<HostInfo> {
    match platform::detect(&ctx.scan_root) {
        OsFamily::Windows => crate::platform::windows::collect_host(ctx),
        OsFamily::Linux => Ok(sources::host::collect(ctx)),
    }
}
