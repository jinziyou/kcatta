//! Installed packages via `dpkg-query` (Debian / Ubuntu / Kali / …).

use std::process::Command;

use scanner_contract::{Asset, Package};

/// Collect installed packages. Returns an empty list when `dpkg-query` is missing
/// or fails (non-Debian hosts).
pub fn collect() -> Vec<Asset> {
    collect_dpkg().unwrap_or_default()
}

fn collect_dpkg() -> anyhow::Result<Vec<Asset>> {
    let output = Command::new("dpkg-query")
        .args(["-W", "-f=${Package}\t${Version}\n"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "dpkg-query exited with {}",
            output.status.code().unwrap_or(-1)
        );
    }

    let stdout = String::from_utf8(output.stdout)?;
    Ok(parse_dpkg_output(&stdout))
}

fn parse_dpkg_output(stdout: &str) -> Vec<Asset> {
    let mut assets = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, version)) = line.split_once('\t') else {
            continue;
        };
        let name = name.trim();
        let version = version.trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        assets.push(Asset::Package(Package {
            asset_id: format!("pkg-{name}"),
            name: name.to_string(),
            version: version.to_string(),
            source: Some("dpkg".to_string()),
            install_path: None,
        }));
    }
    assets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dpkg_output_lines() {
        let out = "openssl\t3.0.2-0ubuntu1.18\ncurl\t7.81.0-1\n\n";
        let assets = parse_dpkg_output(out);
        assert_eq!(assets.len(), 2);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.asset_id, "pkg-openssl");
                assert_eq!(p.name, "openssl");
                assert_eq!(p.version, "3.0.2-0ubuntu1.18");
                assert_eq!(p.source.as_deref(), Some("dpkg"));
            }
            _ => panic!("expected package"),
        }
    }
}
