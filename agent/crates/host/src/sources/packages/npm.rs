//! Globally installed npm packages discovered under the scan root.
//!
//! Reads `package.json` from each package directory in the well-known global
//! `node_modules` locations (including one level of `@scope/` nesting).
//! Project-local trees are found via [`crate::walk::registry`].

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::ScanContext;
use agent_contract::{Asset, Package};

use crate::platform::{self, OsFamily};
use crate::root::{join_root, join_root_path};
use crate::walk::handlers::npm;
use crate::walk::{npm_handler, walk_project};

const ECOSYSTEM: &str = "npm";

/// Global `node_modules` roots (relative to scan root).
const LINUX_MODULE_ROOTS: &[&str] = &["usr/lib/node_modules", "usr/local/lib/node_modules"];

/// Installed npm packages (global + configured project roots) as [`Asset`]s.
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
    for root in module_roots(ctx) {
        push(read_modules(&root), &mut assets);
    }
    let handler = npm_handler();
    for root in &ctx.project_roots {
        push(
            walk_project(&join_root_path(ctx, root), &handler),
            &mut assets,
        );
    }
    assets
}

fn module_roots(ctx: &ScanContext) -> Vec<std::path::PathBuf> {
    if platform::detect(&ctx.scan_root) == OsFamily::Windows {
        return windows_module_roots(ctx);
    }
    LINUX_MODULE_ROOTS
        .iter()
        .map(|rel| join_root(ctx, rel))
        .collect()
}

fn windows_module_roots(ctx: &ScanContext) -> Vec<std::path::PathBuf> {
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
        if let Ok(profiles) = fs::read_dir(&users) {
            for profile in profiles.flatten() {
                let npm = profile.path().join("AppData/Roaming/npm/node_modules");
                if npm.is_dir() {
                    roots.push(npm);
                }
            }
        }
    }
    roots
}

fn read_modules(dir: &Path) -> Vec<(String, String)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name.starts_with('@') {
            out.extend(read_scope(&entry.path()));
        } else if file_name == ".bin" {
            continue;
        } else if let Some(pkg) = npm::parse_package_json(&entry.path().join("package.json")) {
            out.push(pkg);
        }
    }
    out
}

fn read_scope(scope_dir: &Path) -> Vec<(String, String)> {
    let Ok(entries) = fs::read_dir(scope_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| npm::parse_package_json(&entry.path().join("package.json")))
        .collect()
}

fn into_asset(name: String, version: String) -> Asset {
    Asset::Package(Package {
        asset_id: format!("npm-{name}"),
        name,
        version,
        source: Some("npm".to_string()),
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
}
