//! Installed packages from `var/lib/dpkg/status` under the scan root.

use scanner_contract::{Asset, Package};

use crate::root::join_root;
use scanner_runtime::ScanContext;

const DPKG_STATUS: &str = "var/lib/dpkg/status";

pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let path = join_root(ctx, DPKG_STATUS);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    parse_dpkg_status(&text)
}

pub fn parse_dpkg_status(content: &str) -> Vec<Asset> {
    let mut assets = Vec::new();
    for stanza in content.split("\n\n") {
        let stanza = stanza.trim();
        if stanza.is_empty() {
            continue;
        }
        let mut name = None;
        let mut version = None;
        let mut installed = false;
        for line in stanza.lines() {
            if let Some(v) = line.strip_prefix("Package: ") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = Some(v.trim().to_string());
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
        assets.push(Asset::Package(Package {
            asset_id: format!("pkg-{name}"),
            name,
            version,
            source: Some("dpkg".to_string()),
            install_path: None,
        }));
    }
    assets
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
Version: 3.0.2-0ubuntu1.18

Package: curl
Status: deinstall ok config-files
Version: 7.81.0-1
";
        let assets = parse_dpkg_status(content);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.name, "openssl");
                assert_eq!(p.version, "3.0.2-0ubuntu1.18");
            }
            _ => panic!("expected package"),
        }
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
