//! Installed Python distributions discovered under the scan root.
//!
//! Reads `*.dist-info/METADATA` and `*.egg-info/PKG-INFO` files in the
//! well-known global `site-packages` / `dist-packages` directories (no
//! full-tree walk). Project-local venvs are found via [`crate::walk::registry`].

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ScanContext;
use agent_contract::{Asset, Package};

use crate::platform::{self, OsFamily};
use crate::root::{join_root, join_root_path};
use crate::walk::handlers::pypi;
use crate::walk::{pypi_handler, walk_project};

const ECOSYSTEM: &str = "PyPI";

/// Base directories (relative to root) that hold `pythonX.Y` interpreter trees.
const LINUX_LIB_BASES: &[&str] = &["usr/lib", "usr/local/lib"];

/// Installed Python packages as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut assets = Vec::new();
    let mut push = |items: Vec<(String, String)>, assets: &mut Vec<Asset>| {
        for (name, version) in items {
            if seen.insert((name.clone(), version.clone())) {
                assets.push(into_asset(name, version));
            }
        }
    };
    for site in site_packages_dirs(ctx) {
        push(read_site_packages(&site), &mut assets);
    }
    let handler = pypi_handler();
    for root in &ctx.project_roots {
        push(
            walk_project(&join_root_path(ctx, root), &handler),
            &mut assets,
        );
    }
    assets
}

/// Enumerate `.../pythonX.Y/{site,dist}-packages` directories that exist.
fn site_packages_dirs(ctx: &ScanContext) -> Vec<PathBuf> {
    if platform::detect(&ctx.scan_root) == OsFamily::Windows {
        return windows_site_packages_dirs(ctx);
    }
    let mut dirs = Vec::new();
    for base in LINUX_LIB_BASES {
        let base_path = join_root(ctx, base);
        dirs.extend(python_site_dirs_under(&base_path));
    }
    dirs
}

fn windows_site_packages_dirs(ctx: &ScanContext) -> Vec<PathBuf> {
    use crate::platform::find_path_case_insensitive;
    use crate::platform::windows::first_existing_dir;

    let mut dirs = Vec::new();
    let root = &ctx.scan_root;
    for parts in [
        &["Program Files", "Python311", "Lib", "site-packages"][..],
        &["Program Files", "Python310", "Lib", "site-packages"][..],
        &["Program Files", "Python39", "Lib", "site-packages"][..],
        &["Program Files (x86)", "Python311", "Lib", "site-packages"][..],
    ] {
        if let Some(path) = find_path_case_insensitive(root, parts) {
            if path.is_dir() {
                dirs.push(path);
            }
        }
    }
    if let Some(users) = first_existing_dir(root, &[&["Users"]]) {
        if let Ok(profiles) = fs::read_dir(&users) {
            for profile in profiles.flatten() {
                let local = profile.path().join("AppData/Local/Programs/Python");
                if !local.is_dir() {
                    continue;
                }
                if let Ok(py_dirs) = fs::read_dir(&local) {
                    for py in py_dirs.flatten() {
                        let site = py.path().join("Lib/site-packages");
                        if site.is_dir() {
                            dirs.push(site);
                        }
                    }
                }
            }
        }
    }
    dirs
}

fn python_site_dirs_under(base_path: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(base_path) else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("python3") {
            continue;
        }
        for leaf in ["site-packages", "dist-packages"] {
            let candidate = entry.path().join(leaf);
            if candidate.is_dir() {
                dirs.push(candidate);
            }
        }
    }
    dirs
}

/// Parse every dist-info / egg-info entry directly under `site`.
fn read_site_packages(site: &Path) -> Vec<(String, String)> {
    let Ok(entries) = fs::read_dir(site) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let metadata_file = if file_name.ends_with(".dist-info") {
            entry.path().join("METADATA")
        } else if file_name.ends_with(".egg-info") {
            entry.path().join("PKG-INFO")
        } else {
            continue;
        };
        if let Some(pkg) = pypi::parse_metadata(&metadata_file) {
            out.push(pkg);
        }
    }
    out
}

fn into_asset(name: String, version: String) -> Asset {
    Asset::Package(Package {
        asset_id: format!("pypi-{name}"),
        parent_asset_id: None,
        name,
        version,
        source: Some("pip".to_string()),
        install_path: None,
        ecosystem: Some(ECOSYSTEM.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_reads_dist_info() {
        let temp = tempfile::tempdir().unwrap();
        let site = temp
            .path()
            .join("usr/lib/python3.11/site-packages/Jinja2-3.1.2.dist-info");
        fs::create_dir_all(&site).unwrap();
        fs::write(
            site.join("METADATA"),
            "Metadata-Version: 2.1\nName: Jinja2\nVersion: 3.1.2\n\nThe description.\n",
        )
        .unwrap();

        let ctx = ScanContext::at(temp.path());
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.name, "jinja2");
                assert_eq!(p.version, "3.1.2");
                assert_eq!(p.ecosystem.as_deref(), Some("PyPI"));
                assert_eq!(p.source.as_deref(), Some("pip"));
            }
            other => panic!("expected package, got {other:?}"),
        }
    }

    #[test]
    fn collect_scans_project_venv() {
        let temp = tempfile::tempdir().unwrap();
        let dist = temp
            .path()
            .join("srv/app/.venv/lib/python3.11/site-packages/Flask-3.0.0.dist-info");
        fs::create_dir_all(&dist).unwrap();
        fs::write(dist.join("METADATA"), "Name: Flask\nVersion: 3.0.0\n").unwrap();

        let ctx = ScanContext::at(temp.path()).with_project_roots(vec![PathBuf::from("srv/app")]);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.name, "flask");
                assert_eq!(p.version, "3.0.0");
                assert_eq!(p.ecosystem.as_deref(), Some("PyPI"));
            }
            other => panic!("expected package, got {other:?}"),
        }
    }

    #[test]
    fn collect_dedupes_same_name_version() {
        let temp = tempfile::tempdir().unwrap();
        for py in ["python3.10", "python3.11"] {
            let site = temp
                .path()
                .join(format!("usr/lib/{py}/dist-packages/pyyaml-6.0.dist-info"));
            fs::create_dir_all(&site).unwrap();
            fs::write(site.join("METADATA"), "Name: PyYAML\nVersion: 6.0\n").unwrap();
        }
        let ctx = ScanContext::at(temp.path());
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
    }
}
