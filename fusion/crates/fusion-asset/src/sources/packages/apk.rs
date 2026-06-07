//! Installed packages from Alpine's apk database (`lib/apk/db/installed`).
//!
//! The apk installed DB is a plain-text file of blank-line-separated stanzas
//! with single-letter keys (`P:` name, `V:` version), so it parses much like
//! `dpkg/status`. Packages are tagged with the host's OSV ecosystem (e.g.
//! `Alpine:v3.18`) for vulnerability matching in `form`.

use fusion_contract::{Asset, Package};

use crate::root::join_root;
use crate::sbom::read_distro;
use fusion_runtime::ScanContext;

const APK_DB: &str = "lib/apk/db/installed";

/// One installed apk package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkPackage {
    pub name: String,
    pub version: String,
}

/// Installed apk packages as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let ecosystem = read_distro(ctx).osv_ecosystem();
    apk_packages(ctx)
        .into_iter()
        .map(|pkg| into_asset(pkg, ecosystem.clone()))
        .collect()
}

fn apk_packages(ctx: &ScanContext) -> Vec<ApkPackage> {
    let path = join_root(ctx, APK_DB);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_installed(&text),
        Err(_) => Vec::new(),
    }
}

/// Parse the apk installed DB into packages, one per `P:`/`V:` stanza.
pub fn parse_installed(content: &str) -> Vec<ApkPackage> {
    let mut packages = Vec::new();
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
            continue;
        };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        packages.push(ApkPackage { name, version });
    }
    packages
}

fn into_asset(pkg: ApkPackage, ecosystem: Option<String>) -> Asset {
    Asset::Package(Package {
        asset_id: format!("apk-{}", pkg.name),
        name: pkg.name,
        version: pkg.version,
        source: Some("apk".to_string()),
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
}
