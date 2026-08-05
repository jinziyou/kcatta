//! Globally installed npm packages discovered under the scan root.
//!
//! Reads `package.json` from each package directory in the well-known global
//! `node_modules` locations (including one level of `@scope/` nesting).
//! Project-local trees are found via [`crate::walk::registry`].

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

use crate::ScanContext;
use agent_contract::{Asset, Package};

use crate::platform::{self, OsFamily};
use crate::root::{join_root, join_root_path};
use crate::walk::handlers::npm;
use crate::walk::{npm_handler, walk_project_with_diagnostics};

use super::PackageCoverage;

const ECOSYSTEM: &str = "npm";

/// Global `node_modules` roots (relative to scan root).
const LINUX_MODULE_ROOTS: &[&str] = &["usr/lib/node_modules", "usr/local/lib/node_modules"];

/// Installed npm packages (global + configured project roots) as [`Asset`]s.
#[allow(dead_code)] // Compatibility wrapper for direct source callers.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    collect_with_coverage(ctx).0
}

pub(crate) fn collect_with_coverage(ctx: &ScanContext) -> (Vec<Asset>, PackageCoverage) {
    let mut coverage = PackageCoverage::default();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut assets = Vec::new();
    let mut push = |items: Vec<(String, String)>, assets: &mut Vec<Asset>| {
        for (name, version) in items {
            if seen.insert((name.clone(), version.clone())) {
                assets.push(into_asset(name, version));
            }
        }
    };
    for root in module_roots(ctx, &mut coverage) {
        push(read_modules(&root, &mut coverage), &mut assets);
    }
    let handler = npm_handler();
    for root in &ctx.project_roots {
        let (items, diagnostics) =
            walk_project_with_diagnostics(&join_root_path(ctx, root), &handler);
        coverage.merge_incomplete(diagnostics.incomplete());
        push(items, &mut assets);
    }
    (assets, coverage)
}

fn module_roots(ctx: &ScanContext, coverage: &mut PackageCoverage) -> Vec<std::path::PathBuf> {
    if platform::detect(&ctx.scan_root) == OsFamily::Windows {
        return windows_module_roots(ctx, coverage);
    }
    LINUX_MODULE_ROOTS
        .iter()
        .map(|rel| join_root(ctx, rel))
        .collect()
}

fn windows_module_roots(
    ctx: &ScanContext,
    coverage: &mut PackageCoverage,
) -> Vec<std::path::PathBuf> {
    use crate::platform::find_path_case_insensitive;
    use crate::platform::windows::first_existing_dir;

    let mut roots = Vec::new();
    let scan_root = &ctx.scan_root;
    for parts in [
        &["Program Files", "nodejs", "node_modules"][..],
        &["Program Files (x86)", "nodejs", "node_modules"][..],
    ] {
        if let Some(path) = find_path_case_insensitive(scan_root, parts) {
            roots.push(path);
        }
    }
    if let Some(users) = first_existing_dir(scan_root, &[&["Users"]]) {
        match fs::read_dir(&users) {
            Ok(profiles) => {
                for item in profiles {
                    let profile = match item {
                        Ok(profile) => profile,
                        Err(_) => {
                            coverage.mark_incomplete();
                            continue;
                        }
                    };
                    let npm = profile.path().join("AppData/Roaming/npm/node_modules");
                    if npm.is_dir() {
                        roots.push(npm);
                    }
                }
            }
            Err(_) => coverage.mark_incomplete(),
        }
    }
    roots
}

fn read_modules(dir: &Path, coverage: &mut PackageCoverage) -> Vec<(String, String)> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            coverage.mark_incomplete();
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for item in entries {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                coverage.mark_incomplete();
                continue;
            }
        };
        match fs::metadata(entry.path()) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => continue,
            Err(_) => {
                coverage.mark_incomplete();
                continue;
            }
        }
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name.starts_with('@') {
            out.extend(read_scope(&entry.path(), coverage));
        } else if file_name == ".bin" {
            continue;
        } else if let Some(pkg) = npm::parse_package_json(&entry.path().join("package.json")) {
            out.push(pkg);
        } else {
            coverage.mark_incomplete();
        }
    }
    out
}

fn read_scope(scope_dir: &Path, coverage: &mut PackageCoverage) -> Vec<(String, String)> {
    let entries = match fs::read_dir(scope_dir) {
        Ok(entries) => entries,
        Err(_) => {
            coverage.mark_incomplete();
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for item in entries {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                coverage.mark_incomplete();
                continue;
            }
        };
        match fs::metadata(entry.path()) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => continue,
            Err(_) => {
                coverage.mark_incomplete();
                continue;
            }
        }
        match npm::parse_package_json(&entry.path().join("package.json")) {
            Some(package) => out.push(package),
            None => coverage.mark_incomplete(),
        }
    }
    out
}

fn into_asset(name: String, version: String) -> Asset {
    Asset::Package(Package {
        asset_id: format!("npm-{name}"),
        parent_asset_id: None,
        name,
        version,
        source: Some("npm".to_string()),
        source_name: None,
        source_version: None,
        install_path: None,
        ecosystem: Some(ECOSYSTEM.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pkg(dir: &Path, name: &str, version: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
    }

    #[test]
    fn collect_reads_global_modules() {
        let temp = tempfile::tempdir().unwrap();
        let modules = temp.path().join("usr/lib/node_modules");
        write_pkg(&modules.join("lodash"), "lodash", "4.17.21");
        write_pkg(&modules.join("@babel/core"), "@babel/core", "7.0.0");

        let ctx = ScanContext::at(temp.path());
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 2);

        let mut names: Vec<_> = assets
            .iter()
            .map(|a| match a {
                Asset::Package(p) => (p.name.clone(), p.ecosystem.clone()),
                other => panic!("expected package, got {other:?}"),
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                ("@babel/core".to_string(), Some("npm".to_string())),
                ("lodash".to_string(), Some("npm".to_string())),
            ]
        );
    }

    #[test]
    fn collect_scans_project_node_modules() {
        let temp = tempfile::tempdir().unwrap();
        write_pkg(
            &temp.path().join("srv/app/node_modules/express"),
            "express",
            "4.18.2",
        );
        write_pkg(
            &temp
                .path()
                .join("srv/app/node_modules/express/node_modules/qs"),
            "qs",
            "6.11.0",
        );
        write_pkg(&temp.path().join("srv/app"), "my-app", "0.1.0");

        let ctx = ScanContext::at(temp.path())
            .with_project_roots(vec![std::path::PathBuf::from("srv/app")]);
        let assets = collect(&ctx);
        let mut names: Vec<&str> = assets
            .iter()
            .map(|a| match a {
                Asset::Package(p) => p.name.as_str(),
                other => panic!("expected package, got {other:?}"),
            })
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["express", "qs"]);
    }

    #[test]
    fn coverage_marks_package_json_parse_failures() {
        let temp = tempfile::tempdir().unwrap();
        let package = temp.path().join("usr/lib/node_modules/bad");
        fs::create_dir_all(&package).unwrap();
        fs::write(package.join("package.json"), "not-json").unwrap();
        let (assets, coverage) = collect_with_coverage(&ScanContext::at(temp.path()));
        assert!(assets.is_empty());
        assert!(coverage.source_incomplete());
    }
}
