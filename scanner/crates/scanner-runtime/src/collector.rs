//! Pluggable collector interface used by domain crates (`scanner-asset`,
//! `scanner-vuln`, `scanner-malware`, ...).

use std::path::{Path, PathBuf};

use scanner_contract::{Asset, HostInfo, Vulnerability};

/// Mutable state shared across collectors in one scan cycle.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Filesystem root of the scan target (mounted image, chroot, or `/`).
    pub scan_root: PathBuf,
    pub host_id: Option<String>,
    pub host: Option<HostInfo>,
}

impl ScanContext {
    pub fn at(scan_root: impl AsRef<Path>) -> Self {
        Self {
            scan_root: scan_root.as_ref().to_path_buf(),
            host_id: None,
            host: None,
        }
    }
}

impl Default for ScanContext {
    fn default() -> Self {
        Self::at("/")
    }
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
