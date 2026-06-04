//! Installed packages from `var/lib/dpkg/status` under the scan root.

use probe_contract::{Asset, Package};

use crate::root::join_root;
use crate::sbom::read_distro;
use probe_runtime::ScanContext;

const DPKG_STATUS: &str = "var/lib/dpkg/status";

/// One installed dpkg package, with the fields needed for both the asset
/// inventory (`packages.json`) and SBOM purl construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebPackage {
    /// Package name (`Package:` field).
    pub name: String,
    /// Installed version string.
    pub version: String,
    /// `Architecture:` when present.
    pub arch: Option<String>,
}

/// Installed packages as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let ecosystem = read_distro(ctx).osv_ecosystem();
    deb_packages(ctx)
        .into_iter()
        .map(|pkg| into_asset(pkg, ecosystem.clone()))
        .collect()
}

/// Installed packages as [`DebPackage`]s (used by the SBOM builder).
pub fn deb_packages(ctx: &ScanContext) -> Vec<DebPackage> {
    let path = join_root(ctx, DPKG_STATUS);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_dpkg_status(&text),
        Err(_) => Vec::new(),
    }
}

/// Parse `dpkg/status` stanzas, keeping only currently-installed packages.
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

pub(crate) fn into_asset(pkg: DebPackage, ecosystem: Option<String>) -> Asset {
    Asset::Package(Package {
        asset_id: format!("pkg-{}", pkg.name),
        name: pkg.name,
        version: pkg.version,
        source: Some("dpkg".to_string()),
        install_path: None,
        ecosystem,
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

    #[test]
    fn collect_sets_ecosystem_from_os_release() {
        let temp = tempfile::tempdir().unwrap();
        let status_path = temp.path().join("var/lib/dpkg/status");
        std::fs::create_dir_all(status_path.parent().unwrap()).unwrap();
        std::fs::write(
            &status_path,
            "Package: acl\nStatus: install ok installed\nVersion: 2.3.2-3\n",
        )
        .unwrap();
        let os_release = temp.path().join("etc/os-release");
        std::fs::create_dir_all(os_release.parent().unwrap()).unwrap();
        std::fs::write(&os_release, "ID=debian\nVERSION_ID=\"12\"\n").unwrap();

        let ctx = ScanContext::at(temp.path());
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => assert_eq!(p.ecosystem.as_deref(), Some("Debian:12")),
            other => panic!("expected package, got {other:?}"),
        }
    }
}
