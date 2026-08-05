//! Installed services collector (Linux fixed paths or Windows registry).

use crate::{Collector, CollectorOutput, ScanContext};
use agent_contract::Asset;

use crate::platform::{self, OsFamily};
use crate::sources;

/// Collects installed services from systemd unit files and SysV `init.d`.
pub struct ServicesCollector;

impl Collector for ServicesCollector {
    fn id(&self) -> &'static str {
        "services"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "services")?;
        Ok(CollectorOutput::Assets(collect(ctx)))
    }
}

/// Installed services as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    collect_with_coverage(ctx).0
}

/// Installed services plus source diagnostics from the same pass.
pub(crate) fn collect_with_coverage(
    ctx: &ScanContext,
) -> (Vec<Asset>, sources::services::ServiceCoverage) {
    if platform::detect(&ctx.scan_root) == OsFamily::Windows {
        return (
            crate::platform::windows::collect_services(ctx),
            sources::services::ServiceCoverage::incomplete(),
        );
    }
    sources::services::collect_with_coverage(ctx)
}
