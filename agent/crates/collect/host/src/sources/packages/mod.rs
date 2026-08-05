//! Fixed-path and walk-assisted package inventory sources.

pub mod apk;
pub mod dpkg;
pub mod npm;
pub mod pypi;
pub mod rpm;

pub use dpkg::{deb_packages, DebPackage};

use crate::ScanContext;

/// Same-pass diagnostics shared by installed and language package sources.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PackageCoverage {
    source_incomplete: bool,
}

impl PackageCoverage {
    pub(crate) fn source_incomplete(self) -> bool {
        self.source_incomplete
    }

    pub(crate) fn mark_incomplete(&mut self) {
        self.source_incomplete = true;
    }

    pub(crate) fn merge_incomplete(&mut self, incomplete: bool) {
        self.source_incomplete |= incomplete;
    }
}

/// PyPI and npm packages (shared by Linux and Windows inventory).
pub fn collect_language_packages(ctx: &ScanContext) -> Vec<agent_contract::Asset> {
    collect_language_packages_with_coverage(ctx).0
}

pub(crate) fn collect_language_packages_with_coverage(
    ctx: &ScanContext,
) -> (Vec<agent_contract::Asset>, PackageCoverage) {
    let (mut assets, mut coverage) = pypi::collect_with_coverage(ctx);
    let (npm_assets, npm_coverage) = npm::collect_with_coverage(ctx);
    assets.extend(npm_assets);
    coverage.merge_incomplete(npm_coverage.source_incomplete());
    (assets, coverage)
}
