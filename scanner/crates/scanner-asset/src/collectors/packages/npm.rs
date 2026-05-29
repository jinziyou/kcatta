//! Globally installed npm packages discovered under the scan root.
//!
//! Reads `package.json` from each package directory in the well-known global
//! `node_modules` locations (including one level of `@scope/` nesting). No
//! full-tree walk: project-local `node_modules` are out of scope here.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use scanner_contract::{Asset, Package};
use scanner_runtime::ScanContext;

use crate::root::join_root;

const ECOSYSTEM: &str = "npm";

/// Global `node_modules` roots (relative to scan root).
const MODULE_ROOTS: &[&str] = &["usr/lib/node_modules", "usr/local/lib/node_modules"];

/// Globally installed npm packages as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut assets = Vec::new();
    for root in MODULE_ROOTS {
        for (name, version) in read_modules(&join_root(ctx, root)) {
            if seen.insert((name.clone(), version.clone())) {
                assets.push(into_asset(name, version));
            }
        }
    }
    assets
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
            // Scoped packages: @scope/<pkg>/package.json one level down.
            out.extend(read_scope(&entry.path()));
        } else if file_name == ".bin" {
            continue;
        } else if let Some(pkg) = parse_package_json(&entry.path().join("package.json")) {
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
        .filter_map(|entry| parse_package_json(&entry.path().join("package.json")))
        .collect()
}

fn parse_package_json(path: &Path) -> Option<(String, String)> {
    let text = fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let name = value.get("name")?.as_str()?.to_string();
    let version = value.get("version")?.as_str()?.to_string();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
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
}
