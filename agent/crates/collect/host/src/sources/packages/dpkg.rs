//! Installed packages from `var/lib/dpkg/status` under the scan root.

use agent_contract::{Asset, Package};
use std::io;

use super::PackageCoverage;
use crate::root::join_root;
use crate::sbom::read_distro;
use crate::ScanContext;

const DPKG_STATUS: &str = "var/lib/dpkg/status";

/// One installed dpkg package, with the fields needed for both the asset
/// inventory (`packages.json`) and SBOM purl construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebPackage {
    /// Package name (`Package:` field).
    pub name: String,
    /// Installed version string.
    pub version: String,
    /// Debian source package name (falls back to the binary package name).
    pub source_name: String,
    /// Debian source version (falls back to the installed binary version).
    pub source_version: String,
    /// `Architecture:` when present.
    pub arch: Option<String>,
}

/// Installed packages as contract [`Asset`]s.
#[allow(dead_code)] // Compatibility wrapper for direct source callers.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    collect_with_coverage(ctx).0
}

pub(crate) fn collect_with_coverage(ctx: &ScanContext) -> (Vec<Asset>, PackageCoverage) {
    let mut coverage = PackageCoverage::default();
    let ecosystem = read_distro(ctx).osv_ecosystem();
    let assets = deb_packages_with_coverage(ctx, &mut coverage)
        .into_iter()
        .map(|pkg| into_asset(pkg, ecosystem.clone()))
        .collect();
    (assets, coverage)
}

/// Installed packages as [`DebPackage`]s (used by the SBOM builder).
pub fn deb_packages(ctx: &ScanContext) -> Vec<DebPackage> {
    let mut coverage = PackageCoverage::default();
    deb_packages_with_coverage(ctx, &mut coverage)
}

pub(crate) fn deb_packages_with_coverage(
    ctx: &ScanContext,
    coverage: &mut PackageCoverage,
) -> Vec<DebPackage> {
    let path = join_root(ctx, DPKG_STATUS);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let (packages, malformed) = parse_dpkg_status_with_diagnostics(&text);
            coverage.merge_incomplete(malformed);
            packages
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(_) => {
            coverage.mark_incomplete();
            Vec::new()
        }
    }
}

/// Parse `dpkg/status` stanzas, keeping only currently-installed packages.
#[allow(dead_code)] // Public parser retained for crate tests and callers.
pub fn parse_dpkg_status(content: &str) -> Vec<DebPackage> {
    parse_dpkg_status_with_diagnostics(content).0
}

fn parse_dpkg_status_with_diagnostics(content: &str) -> (Vec<DebPackage>, bool) {
    let mut packages = Vec::new();
    let mut malformed = false;
    for stanza in content.split("\n\n") {
        let stanza = stanza.trim();
        if stanza.is_empty() {
            continue;
        }
        let mut name = None;
        let mut version = None;
        let mut arch = None;
        let mut source = None;
        let mut installed = false;
        let mut has_status = false;
        let mut status_valid = false;
        for line in stanza.lines() {
            if let Some(v) = line.strip_prefix("Package: ") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Architecture: ") {
                arch = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Source: ") {
                source = parse_source_field(v.trim());
            } else if let Some(v) = line.strip_prefix("Status: ") {
                has_status = true;
                status_valid = v.split_whitespace().count() >= 3;
                installed = v.contains("installed") && !v.contains("deinstall");
            }
        }
        let (Some(name), Some(version)) = (name, version) else {
            malformed = true;
            continue;
        };
        if !has_status || !status_valid {
            malformed = true;
            continue;
        }
        if name.is_empty() || version.is_empty() {
            malformed = true;
            continue;
        }
        if !installed {
            continue;
        }
        let (source_name, source_version) = source
            .map(|(source_name, source_version)| {
                (
                    source_name,
                    source_version.unwrap_or_else(|| version.clone()),
                )
            })
            .unwrap_or_else(|| (name.clone(), version.clone()));
        packages.push(DebPackage {
            name,
            version,
            source_name,
            source_version,
            arch: arch.filter(|a| !a.is_empty()),
        });
    }
    (packages, malformed)
}

fn parse_source_field(value: &str) -> Option<(String, Option<String>)> {
    if value.is_empty() {
        return None;
    }
    if let Some((name, version)) = value.split_once(" (") {
        return Some((
            name.trim().to_string(),
            version.strip_suffix(')').map(str::trim).map(str::to_string),
        ));
    }
    Some((value.to_string(), None))
}

pub(crate) fn into_asset(pkg: DebPackage, ecosystem: Option<String>) -> Asset {
    Asset::Package(Package {
        asset_id: format!("pkg-{}", pkg.name),
        parent_asset_id: None,
        name: pkg.name,
        version: pkg.version,
        source: Some("dpkg".to_string()),
        source_name: Some(pkg.source_name),
        source_version: Some(pkg.source_version),
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
Source: openssl-source (3.0.2-0ubuntu1.18)
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
        assert_eq!(packages[0].source_name, "openssl-source");
        assert_eq!(packages[0].source_version, "3.0.2-0ubuntu1.18");
        assert_eq!(packages[0].arch.as_deref(), Some("amd64"));
    }

    #[test]
    fn source_metadata_falls_back_to_binary_package() {
        let content = "\
Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.37-2
";
        let packages = parse_dpkg_status(content);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].source_name, "bash");
        assert_eq!(packages[0].source_version, "5.2.37-2");
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

    #[test]
    fn coverage_marks_existing_dpkg_status_parse_failures() {
        let temp = tempfile::tempdir().unwrap();
        let status = temp.path().join(DPKG_STATUS);
        std::fs::create_dir_all(status.parent().unwrap()).unwrap();
        std::fs::write(
            &status,
            "Package: missing-version\nStatus: install ok installed\n",
        )
        .unwrap();
        let (assets, coverage) = collect_with_coverage(&ScanContext::at(temp.path()));
        assert!(assets.is_empty());
        assert!(coverage.source_incomplete());
    }
}
