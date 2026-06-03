//! Assemble an [`AssetReport`] from per-asset JSON pulled back from a remote scan.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use chrono::Utc;
use probe_contract::{Asset, AssetReport, HostInfo, Vulnerability};
use uuid::Uuid;

const MALWARE_JSON: &str = "malware.json";
const ASSET_JSON_FILES: &[&str] = &[
    "packages.json",
    "services.json",
    "accounts.json",
    "credentials.json",
];

/// Build an [`AssetReport`] from `host.json` / `packages.json` under `output_dir`.
///
/// `host.json` is required (use `--target host` or `all`). `packages.json` is
/// optional and merged into `assets` when present.
pub fn assemble_asset_report(output_dir: &Path) -> anyhow::Result<AssetReport> {
    let host_path = output_dir.join("host.json");
    if !host_path.is_file() {
        bail!(
            "host.json missing under {}; ingest requires --target host or all",
            output_dir.display()
        );
    }

    let host = read_json::<HostInfo>(&host_path)
        .with_context(|| format!("parse host.json at {}", host_path.display()))?;

    let assets = read_merged_assets(output_dir)?;

    Ok(AssetReport {
        report_id: format!("report-{}", Uuid::new_v4()),
        collected_at: Utc::now(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        host,
        assets,
        vulnerabilities: Vec::new(),
    })
}

/// Like [`assemble_asset_report`], but merges `malware.json` when present.
pub fn finalize_asset_report(output_dir: &Path) -> anyhow::Result<AssetReport> {
    let mut report = assemble_asset_report(output_dir)?;
    attach_malware(&mut report, output_dir);
    Ok(report)
}

/// Merge ClamAV hits from `malware.json`, rebinding `affected_asset_id` to the host.
pub fn attach_malware(report: &mut AssetReport, output_dir: &Path) {
    let path = output_dir.join(MALWARE_JSON);
    let Ok(text) = fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut vulns) = serde_json::from_str::<Vec<Vulnerability>>(&text) else {
        return;
    };
    let host_id = report.host.host_id.clone();
    for v in &mut vulns {
        v.affected_asset_id = host_id.clone();
    }
    report.vulnerabilities = vulns;
}

/// Write `asset_report.json` next to the pulled per-asset files.
pub fn write_asset_report(output_dir: &Path, report: &AssetReport) -> anyhow::Result<PathBuf> {
    let path = output_dir.join("asset_report.json");
    let file = fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(file, report)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

fn read_merged_assets(output_dir: &Path) -> anyhow::Result<Vec<Asset>> {
    let mut assets = Vec::new();
    for fname in ASSET_JSON_FILES {
        let path = output_dir.join(fname);
        if !path.is_file() {
            continue;
        }
        let batch = read_json::<Vec<Asset>>(&path)
            .with_context(|| format!("parse {fname} at {}", path.display()))?;
        assets.extend(batch);
    }
    Ok(assets)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("decode JSON from {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe_contract::Asset;

    fn sample_host() -> HostInfo {
        HostInfo {
            host_id: "host-demo-root".to_string(),
            hostname: "demo".to_string(),
            os: "Ubuntu 22.04".to_string(),
            kernel: None,
            arch: Some("x86_64".to_string()),
            ip_addrs: Vec::new(),
            mac_addrs: Vec::new(),
            boot_time: None,
        }
    }

    #[test]
    fn assembles_host_and_packages() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("host.json"),
            serde_json::to_string(&sample_host()).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.path().join("packages.json"),
            serde_json::json!([{
                "kind": "package",
                "asset_id": "pkg-openssl",
                "name": "openssl",
                "version": "3.0.2",
                "source": "dpkg",
                "install_path": null,
                "ecosystem": "Ubuntu:22.04"
            }])
            .to_string(),
        )
        .unwrap();

        let report = assemble_asset_report(dir.path()).unwrap();
        assert_eq!(report.host.hostname, "demo");
        assert_eq!(report.assets.len(), 1);
        assert!(matches!(&report.assets[0], Asset::Package(p) if p.name == "openssl"));
        assert!(report.vulnerabilities.is_empty());
    }

    #[test]
    fn host_only_report_has_empty_assets() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("host.json"),
            serde_json::to_string(&sample_host()).unwrap(),
        )
        .unwrap();

        let report = assemble_asset_report(dir.path()).unwrap();
        assert!(report.assets.is_empty());
    }

    #[test]
    fn missing_host_json_is_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("packages.json"), "[]").unwrap();
        assert!(assemble_asset_report(dir.path()).is_err());
    }

    #[test]
    fn merges_malware_json_into_vulnerabilities() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("host.json"),
            serde_json::to_string(&sample_host()).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.path().join("malware.json"),
            serde_json::json!([{
                "vuln_id": "Eicar-Test-Signature",
                "severity": "critical",
                "cvss_score": null,
                "affected_asset_id": "/tmp/eicar",
                "source": "clamav",
                "evidence": "infected file: /tmp/eicar",
                "references": [],
            }])
            .to_string(),
        )
        .unwrap();

        let report = finalize_asset_report(dir.path()).unwrap();
        assert_eq!(report.vulnerabilities.len(), 1);
        assert_eq!(
            report.vulnerabilities[0].affected_asset_id,
            "host-demo-root"
        );
        assert_eq!(report.vulnerabilities[0].vuln_id, "Eicar-Test-Signature");
    }

    #[test]
    fn writes_asset_report_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("host.json"),
            serde_json::to_string(&sample_host()).unwrap(),
        )
        .unwrap();

        let report = assemble_asset_report(dir.path()).unwrap();
        let path = write_asset_report(dir.path(), &report).unwrap();
        assert_eq!(path.file_name().unwrap(), "asset_report.json");
        let roundtrip: AssetReport =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(roundtrip.host.host_id, "host-demo-root");
    }
}
