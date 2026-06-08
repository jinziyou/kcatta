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
    if platform::detect(&ctx.scan_root) == OsFamily::Windows {
        return crate::platform::windows::collect_accounts(ctx);
    }
    sources::accounts::collect(ctx)
}
