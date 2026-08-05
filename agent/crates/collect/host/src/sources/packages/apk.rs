//! Installed packages from Alpine's apk database (`lib/apk/db/installed`).
//!
//! The apk installed DB is a plain-text file of blank-line-separated stanzas
//! with single-letter keys (`P:` name, `V:` version), so it parses much like
//! `dpkg/status`. Packages are tagged with the host's OSV ecosystem (e.g.
//! `Alpine:v3.18`) for vulnerability matching in `analyzer`.

use agent_contract::{Asset, Package};
use std::io;

use super::PackageCoverage;
use crate::root::join_root;
use crate::sbom::read_distro;
use crate::ScanContext;

const APK_DB: &str = "lib/apk/db/installed";

/// One installed apk package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkPackage {
    pub name: String,
    pub version: String,
}

/// Installed apk packages as contract [`Asset`]s.
#[allow(dead_code)] // Compatibility wrapper for direct source callers.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    collect_with_coverage(ctx).0
}

pub(crate) fn collect_with_coverage(ctx: &ScanContext) -> (Vec<Asset>, PackageCoverage) {
    let mut coverage = PackageCoverage::default();
    let ecosystem = read_distro(ctx).osv_ecosystem();
    let assets = apk_packages(ctx, &mut coverage)
        .into_iter()
        .map(|pkg| into_asset(pkg, ecosystem.clone()))
        .collect();
    (assets, coverage)
}

fn apk_packages(ctx: &ScanContext, coverage: &mut PackageCoverage) -> Vec<ApkPackage> {
    let path = join_root(ctx, APK_DB);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let (packages, malformed) = parse_installed_with_diagnostics(&text);
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

/// Parse the apk installed DB into packages, one per `P:`/`V:` stanza.
#[allow(dead_code)] // Public parser retained for crate tests and callers.
pub fn parse_installed(content: &str) -> Vec<ApkPackage> {
    parse_installed_with_diagnostics(content).0
}

fn parse_installed_with_diagnostics(content: &str) -> (Vec<ApkPackage>, bool) {
    let mut packages = Vec::new();
    let mut malformed = false;
    for stanza in content.split("\n\n") {
        let stanza = stanza.trim();
        if stanza.is_empty() {
            continue;
        }
        let mut name = None;
        let mut version = None;
        for line in stanza.lines() {
            if let Some(v) = line.strip_prefix("P:") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("V:") {
                version = Some(v.trim().to_string());
            }
        }
        let (Some(name), Some(version)) = (name, version) else {
            malformed = true;
            continue;
        };
        if name.is_empty() || version.is_empty() {
            malformed = true;
            continue;
        }
        packages.push(ApkPackage { name, version });
    }
    (packages, malformed)
}

fn into_asset(pkg: ApkPackage, ecosystem: Option<String>) -> Asset {
    Asset::Package(Package {
        asset_id: format!("apk-{}", pkg.name),
        parent_asset_id: None,
        name: pkg.name,
        version: pkg.version,
        source: Some("apk".to_string()),
        source_name: None,
        source_version: None,
        install_path: None,
        ecosystem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_installed_stanzas() {
        let content = "\
C:Q1abc
P:musl
V:1.2.4-r2
A:x86_64

P:busybox
V:1.36.1-r5
A:x86_64
";
        let packages = parse_installed(content);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "musl");
        assert_eq!(packages[0].version, "1.2.4-r2");
        assert_eq!(packages[1].name, "busybox");
    }

    #[test]
    fn collect_sets_alpine_ecosystem() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join(APK_DB);
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        let mut f = std::fs::File::create(&db).unwrap();
        writeln!(f, "P:openssl\nV:3.1.4-r1\nA:x86_64\n").unwrap();
        let os_release = temp.path().join("etc/os-release");
        std::fs::create_dir_all(os_release.parent().unwrap()).unwrap();
        std::fs::write(&os_release, "ID=alpine\nVERSION_ID=3.18.4\n").unwrap();

        let ctx = ScanContext::at(temp.path());
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.name, "openssl");
                assert_eq!(p.source.as_deref(), Some("apk"));
                assert_eq!(p.ecosystem.as_deref(), Some("Alpine:v3.18"));
            }
            other => panic!("expected package, got {other:?}"),
        }
    }

    #[test]
    fn coverage_marks_existing_apk_db_parse_failures() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join(APK_DB);
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        std::fs::write(&db, "P:missing-version\n").unwrap();
        let (assets, coverage) = collect_with_coverage(&ScanContext::at(temp.path()));
        assert!(assets.is_empty());
        assert!(coverage.source_incomplete());
    }
}
