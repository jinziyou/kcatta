//! Local user accounts collector (Linux `etc/passwd` or Windows SAM).

use crate::{Collector, CollectorOutput, ScanContext};
use agent_contract::Asset;

use crate::platform::{self, OsFamily};
use crate::sources;

/// Collects local user accounts from `etc/passwd`.
pub struct AccountsCollector;

impl Collector for AccountsCollector {
    fn id(&self) -> &'static str {
        "accounts"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "accounts")?;
        Ok(CollectorOutput::Assets(collect(ctx)))
    }
}

/// Local accounts as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    collect_with_coverage(ctx).0
}

/// Local accounts plus source diagnostics from the same pass.
pub(crate) fn collect_with_coverage(
    ctx: &ScanContext,
) -> (Vec<Asset>, sources::accounts::AccountCoverage) {
    if platform::detect(&ctx.scan_root) == OsFamily::Windows {
        // Windows registry helpers currently expose no read diagnostics, so
        // do not claim verified completeness from their post-hoc asset list.
        return (
            crate::platform::windows::collect_accounts(ctx),
            sources::accounts::AccountCoverage::incomplete(),
        );
    }
    sources::accounts::collect_with_coverage(ctx)
}
