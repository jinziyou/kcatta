//! Pluggable collector interface used by domain crates (`scanner-asset`,
//! `scanner-vuln`, `scanner-malware`, ...).

use scanner_contract::{Asset, HostInfo, Vulnerability};

/// Mutable state shared across collectors in one scan cycle.
#[derive(Debug, Default)]
pub struct ScanContext {
    pub host_id: Option<String>,
    pub host: Option<HostInfo>,
}

/// What a collector returns after one invocation.
#[derive(Debug, Clone)]
pub enum CollectorOutput {
    Host(HostInfo),
    Assets(Vec<Asset>),
    Vulnerabilities(Vec<Vulnerability>),
}

/// Domain collectors implement this trait; `scanner-cli` (or tests) assemble
/// them into a plan and pass it to [`crate::run_scan`].
pub trait Collector: Send + Sync {
    fn id(&self) -> &'static str;
    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput>;
}
