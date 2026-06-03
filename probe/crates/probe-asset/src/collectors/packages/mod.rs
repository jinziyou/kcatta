//! Installed package collectors.
//!
//! Combines OS packages (dpkg, apk) with language ecosystems (PyPI, npm).
//! Each collector tags its assets with an OSV `ecosystem` so `form` can match
//! a single host's mixed inventory against the right advisory databases.

mod apk;
mod dpkg;
mod npm;
mod pypi;
mod rpm;

pub use dpkg::{deb_packages, DebPackage};

use std::thread;

use crate::discover::discover_project_roots;
use probe_runtime::{Collector, CollectorOutput, ScanContext};

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
    deb_cache: Option<&mut Option<Vec<DebPackage>>>,
) -> Vec<probe_contract::Asset> {
    if crate::platform::detect(&ctx.scan_root) == crate::platform::OsFamily::Windows {
        merge_discovered_project_roots(ctx);
        return crate::windows::collect_packages(ctx);
    }

    merge_discovered_project_roots(ctx);

    let deb_assets = match deb_cache {
        Some(cache) => {
            if cache.is_none() {
                *cache = Some(deb_packages(ctx));
            }
            deb_packages_to_assets(cache.as_ref().expect("deb cache"), ctx)
        }
        None => dpkg::collect(ctx),
    };

    let ctx_ref = &*ctx;
    let (apk_assets, rpm_assets, pypi_assets, npm_assets) = thread::scope(|scope| {
        let apk = scope.spawn(|| apk::collect(ctx_ref));
        let rpm = scope.spawn(|| rpm::collect(ctx_ref));
        let pypi = scope.spawn(|| pypi::collect(ctx_ref));
        let npm = scope.spawn(|| npm::collect(ctx_ref));
        (
            apk.join().expect("apk collector"),
            rpm.join().expect("rpm collector"),
            pypi.join().expect("pypi collector"),
            npm.join().expect("npm collector"),
        )
    });

    let mut assets = deb_assets;
    assets.extend(apk_assets);
    assets.extend(rpm_assets);
    assets.extend(pypi_assets);
    assets.extend(npm_assets);
    assets
}

/// PyPI and npm packages (shared by Linux and Windows inventory).
pub fn collect_language_packages(ctx: &ScanContext) -> Vec<probe_contract::Asset> {
    let mut assets = pypi::collect(ctx);
    assets.extend(npm::collect(ctx));
    assets
}

fn deb_packages_to_assets(
    packages: &[DebPackage],
    ctx: &ScanContext,
) -> Vec<probe_contract::Asset> {
    let ecosystem = crate::sbom::read_distro(ctx).osv_ecosystem();
    packages
        .iter()
        .cloned()
        .map(|pkg| dpkg::into_asset(pkg, ecosystem.clone()))
        .collect()
}

/// Append auto-discovered project roots (deduped, stable order).
fn merge_discovered_project_roots(ctx: &mut ScanContext) {
    for root in discover_project_roots(ctx) {
        if !ctx.project_roots.contains(&root) {
            ctx.project_roots.push(root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe_contract::Asset;

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
        merge_discovered_project_roots(&mut ctx);

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
}
