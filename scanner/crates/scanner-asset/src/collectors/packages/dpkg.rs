//! Installed packages from `var/lib/dpkg/status` under the scan root.

use scanner_contract::{Asset, Package};

use crate::root::join_root;
use scanner_runtime::ScanContext;

const DPKG_STATUS: &str = "var/lib/dpkg/status";

/// One installed dpkg package, with the fields needed for both the asset
/// inventory (`packages.json`) and SBOM purl construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebPackage {
    pub name: String,
    pub version: String,
    pub arch: Option<String>,
}

/// Installed packages as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    deb_packages(ctx).into_iter().map(into_asset).collect()
}

/// Installed packages as [`DebPackage`]s (used by the SBOM builder).
pub fn deb_packages(ctx: &ScanContext) -> Vec<DebPackage> {
    let path = join_root(ctx, DPKG_STATUS);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_dpkg_status(&text),
        Err(_) => Vec::new(),
    }
}

pub fn parse_dpkg_status(content: &str) -> Vec<DebPackage> {
    let mut packages = Vec::new();
    for stanza in content.split("\n\n") {
        let stanza = stanza.trim();
        if stanza.is_empty() {
            continue;
        }
        let mut name = None;
        let mut version = None;
        let mut arch = None;
        let mut installed = false;
        for line in stanza.lines() {
            if let Some(v) = line.strip_prefix("Package: ") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Architecture: ") {
                arch = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Status: ") {
                installed = v.contains("installed") && !v.contains("deinstall");
            }
        }
        let (Some(name), Some(version)) = (name, version) else {
            continue;
        };
        if !installed || name.is_empty() || version.is_empty() {
            continue;
        }
        packages.push(DebPackage {
            name,
            version,
            arch: arch.filter(|a| !a.is_empty()),
        });
    }
    packages
}

fn into_asset(pkg: DebPackage) -> Asset {
    Asset::Package(Package {
        asset_id: format!("pkg-{}", pkg.name),
        name: pkg.name,
        version: pkg.version,
        source: Some("dpkg".to_string()),
        install_path: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_dpkg_status_stanza() {
        let content = "\
Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.2-0ubuntu1.18

Package: curl
Status: deinstall ok config-files
Version: 7.81.0-1
";
        let packages = parse_dpkg_status(content);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "openssl");
        assert_eq!(packages[0].version, "3.0.2-0ubuntu1.18");
        assert_eq!(packages[0].arch.as_deref(), Some("amd64"));
    }

    #[test]
    fn collect_from_fixture_root() {
        let temp = tempfile::tempdir().unwrap();
        let status_path = temp.path().join("var/lib/dpkg/status");
        std::fs::create_dir_all(status_path.parent().unwrap()).unwrap();
        let mut f = std::fs::File::create(&status_path).unwrap();
        writeln!(
            f,
            "Package: acl\nStatus: install ok installed\nVersion: 2.3.2-3\n"
        )
        .unwrap();

        let ctx = ScanContext::at(temp.path());
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
    }
}
