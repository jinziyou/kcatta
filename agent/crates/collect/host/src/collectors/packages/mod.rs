//! Installed package collector (orchestrates fixed-path and walk-assisted sources).

use std::thread;

use crate::sbom::read_distro;
use crate::sources::packages::{self, dpkg};
use crate::walk::discover_project_roots_with_diagnostics;
use crate::{Collector, CollectorOutput, ScanContext};

/// Collects installed packages (dpkg, apk, rpm, PyPI, npm) with OSV ecosystems.
pub struct PackagesCollector;

impl Collector for PackagesCollector {
    fn id(&self) -> &'static str {
        "packages"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "packages")?;
        let assets = collect_packages(ctx, None);
        Ok(CollectorOutput::Assets(assets))
    }
}

/// Collect all package assets. When `deb_cache` is supplied, dpkg status is
/// parsed once and reused (e.g. by the SBOM builder in the same scan pass).
pub fn collect_packages(
    ctx: &mut ScanContext,
    deb_cache: Option<&mut Option<Vec<packages::DebPackage>>>,
) -> Vec<agent_contract::Asset> {
    collect_packages_with_coverage(ctx, deb_cache).0
}

/// Collect packages plus source diagnostics from the same pass.
pub(crate) fn collect_packages_with_coverage(
    ctx: &mut ScanContext,
    deb_cache: Option<&mut Option<Vec<packages::DebPackage>>>,
) -> (Vec<agent_contract::Asset>, packages::PackageCoverage) {
    let mut coverage = packages::PackageCoverage::default();
    if crate::platform::detect(&ctx.scan_root) == crate::platform::OsFamily::Windows {
        merge_discovered_project_roots(ctx, &mut coverage);
        // Registry-backed Windows package readers do not expose diagnostics.
        coverage.mark_incomplete();
        return (crate::platform::windows::collect_packages(ctx), coverage);
    }

    merge_discovered_project_roots(ctx, &mut coverage);

    let deb_assets = match deb_cache {
        Some(cache) => {
            if cache.is_none() {
                *cache = Some(dpkg::deb_packages_with_coverage(ctx, &mut coverage));
            } else {
                // A pre-populated cache has no diagnostics from this pass.
                coverage.mark_incomplete();
            }
            deb_packages_to_assets(cache.as_ref().expect("deb cache"), ctx)
        }
        None => {
            let (assets, source_coverage) = dpkg::collect_with_coverage(ctx);
            coverage.merge_incomplete(source_coverage.source_incomplete());
            assets
        }
    };

    let ctx_ref = &*ctx;
    let (apk_result, rpm_result, pypi_result, npm_result) = thread::scope(|scope| {
        let apk = scope.spawn(|| packages::apk::collect_with_coverage(ctx_ref));
        let rpm = scope.spawn(|| packages::rpm::collect_with_coverage(ctx_ref));
        let pypi = scope.spawn(|| packages::pypi::collect_with_coverage(ctx_ref));
        let npm = scope.spawn(|| packages::npm::collect_with_coverage(ctx_ref));
        (
            apk.join().expect("apk collector"),
            rpm.join().expect("rpm collector"),
            pypi.join().expect("pypi collector"),
            npm.join().expect("npm collector"),
        )
    });

    let mut merge = |source: packages::PackageCoverage| {
        coverage.merge_incomplete(source.source_incomplete());
    };
    let (apk_assets, apk_coverage) = apk_result;
    let (rpm_assets, rpm_coverage) = rpm_result;
    let (pypi_assets, pypi_coverage) = pypi_result;
    let (npm_assets, npm_coverage) = npm_result;
    merge(apk_coverage);
    merge(rpm_coverage);
    merge(pypi_coverage);
    merge(npm_coverage);

    let mut assets = deb_assets;
    assets.extend(apk_assets);
    assets.extend(rpm_assets);
    assets.extend(pypi_assets);
    assets.extend(npm_assets);
    (assets, coverage)
}

/// PyPI and npm packages (shared by Linux and Windows inventory).
pub fn collect_language_packages(ctx: &ScanContext) -> Vec<agent_contract::Asset> {
    packages::collect_language_packages(ctx)
}

fn deb_packages_to_assets(
    packages: &[packages::DebPackage],
    ctx: &ScanContext,
) -> Vec<agent_contract::Asset> {
    let ecosystem = read_distro(ctx).osv_ecosystem();
    packages
        .iter()
        .cloned()
        .map(|pkg| dpkg::into_asset(pkg, ecosystem.clone()))
        .collect()
}

fn merge_discovered_project_roots(ctx: &mut ScanContext, coverage: &mut packages::PackageCoverage) {
    if !ctx.project_discovery {
        return;
    }
    let (roots, diagnostics) = discover_project_roots_with_diagnostics(ctx);
    coverage.merge_incomplete(diagnostics.incomplete());
    for root in roots {
        if !ctx.project_roots.contains(&root) {
            ctx.project_roots.push(root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_contract::Asset;

    #[test]
    fn auto_discovers_project_for_language_packages() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(
            root.join("srv/app/.venv/lib/python3.11/site-packages/Flask-3.0.0.dist-info"),
        )
        .unwrap();
        std::fs::write(
            root.join("srv/app/.venv/lib/python3.11/site-packages/Flask-3.0.0.dist-info/METADATA"),
            "Name: Flask\nVersion: 3.0.0\n",
        )
        .unwrap();
        std::fs::write(root.join("srv/app/pyproject.toml"), "[project]\n").unwrap();

        let mut ctx = ScanContext::at(root);
        ctx.host_id = Some("host-1".into());
        let mut coverage = packages::PackageCoverage::default();
        merge_discovered_project_roots(&mut ctx, &mut coverage);

        let output = PackagesCollector.collect(&mut ctx).unwrap();
        let packages: Vec<_> = match output {
            CollectorOutput::Assets(assets) => assets
                .into_iter()
                .filter(|a| matches!(a, Asset::Package(_)))
                .collect(),
            _ => panic!("expected assets"),
        };
        assert!(
            packages
                .iter()
                .any(|a| matches!(a, Asset::Package(p) if p.name == "flask")),
            "expected flask from auto-discovered project root"
        );
    }

    #[test]
    fn can_disable_project_root_auto_discovery() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("pyproject.toml"), "[project]\n").unwrap();
        let mut ctx = ScanContext::at(temp.path()).with_project_discovery(false);

        let mut coverage = packages::PackageCoverage::default();
        merge_discovered_project_roots(&mut ctx, &mut coverage);

        assert!(ctx.project_roots.is_empty());
    }
}
