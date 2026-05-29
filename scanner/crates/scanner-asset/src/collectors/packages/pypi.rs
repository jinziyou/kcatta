//! Installed Python distributions discovered under the scan root.
//!
//! Reads `*.dist-info/METADATA` and `*.egg-info/PKG-INFO` files in the
//! well-known global `site-packages` / `dist-packages` directories (no
//! full-tree walk). Package names are normalised to PEP 503 form so they
//! match the names used in OSV's `PyPI` ecosystem.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use scanner_contract::{Asset, Package};
use scanner_runtime::ScanContext;

use crate::root::join_root;

const ECOSYSTEM: &str = "PyPI";

/// Base directories (relative to root) that hold `pythonX.Y` interpreter trees.
const LIB_BASES: &[&str] = &["usr/lib", "usr/local/lib"];

/// Installed Python packages as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut assets = Vec::new();
    for site in site_packages_dirs(ctx) {
        for (name, version) in read_site_packages(&site) {
            if seen.insert((name.clone(), version.clone())) {
                assets.push(into_asset(name, version));
            }
        }
    }
    assets
}

/// Enumerate `.../pythonX.Y/{site,dist}-packages` directories that exist.
fn site_packages_dirs(ctx: &ScanContext) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for base in LIB_BASES {
        let base_path = join_root(ctx, base);
        let Ok(entries) = fs::read_dir(&base_path) else {
            continue;
        };
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
        if let Some(pkg) = parse_metadata(&metadata_file) {
            out.push(pkg);
        }
    }
    out
}

/// Pull `Name` / `Version` from an RFC822-style METADATA / PKG-INFO header.
fn parse_metadata(path: &Path) -> Option<(String, String)> {
    let text = fs::read_to_string(path).ok()?;
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        // Headers end at the first blank line; the body (description) follows.
        if line.is_empty() {
            break;
        }
        if let Some(v) = line.strip_prefix("Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
    }
    let (name, version) = (name?, version?);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((normalize_name(&name), version))
}

/// PEP 503 normalisation: lowercase and collapse runs of `-`, `_`, `.` to a
/// single `-`. OSV keys PyPI advisories by this normalised form.
fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.extend(ch.to_lowercase());
            prev_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

fn into_asset(name: String, version: String) -> Asset {
    Asset::Package(Package {
        asset_id: format!("pypi-{name}"),
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
    fn normalize_pep503() {
        assert_eq!(normalize_name("Flask"), "flask");
        assert_eq!(normalize_name("ruamel.yaml"), "ruamel-yaml");
        assert_eq!(normalize_name("typing_extensions"), "typing-extensions");
        assert_eq!(normalize_name("Foo--_.Bar"), "foo-bar");
    }

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
                assert_eq!(p.name, "jinja2"); // normalised
                assert_eq!(p.version, "3.1.2");
                assert_eq!(p.ecosystem.as_deref(), Some("PyPI"));
                assert_eq!(p.source.as_deref(), Some("pip"));
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
