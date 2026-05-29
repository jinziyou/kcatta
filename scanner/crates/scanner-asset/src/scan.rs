//! Static filesystem scan API: mount root + target → per-asset JSON files.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use scanner_contract::Asset;
use scanner_runtime::{Collector, CollectorOutput, ScanContext};

use crate::collectors::{HostCollector, PackagesCollector};

/// What to extract from the mounted tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanTarget {
    /// `host.json` only.
    #[default]
    Host,
    /// `packages.json` only.
    Packages,
    /// `sbom.cyclonedx.json` only (CycloneDX SBOM for `trivy sbom`).
    Sbom,
    /// `host.json`, `packages.json`, and `sbom.cyclonedx.json`.
    All,
}

impl ScanTarget {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "packages" | "package" => Ok(Self::Packages),
            "sbom" | "cyclonedx" => Ok(Self::Sbom),
            "all" => Ok(Self::All),
            "ports" | "port" => anyhow::bail!(
                "port scanning is not supported by scanner-asset (use host|packages|sbom|all)"
            ),
            other => {
                anyhow::bail!("unknown scan target {other:?} (use host|packages|sbom|all)")
            }
        }
    }

    fn targets(self) -> &'static [ScanTarget] {
        match self {
            Self::Host => &[Self::Host],
            Self::Packages => &[Self::Packages],
            Self::Sbom => &[Self::Sbom],
            Self::All => &[Self::Host, Self::Packages, Self::Sbom],
        }
    }
}

/// Static scan parameters.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Mounted filesystem root (default `/`).
    pub root: PathBuf,
    /// Scan object (default [`ScanTarget::Host`]).
    pub target: ScanTarget,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            target: ScanTarget::Host,
        }
    }
}

/// Paths of JSON files written by [`run_static_scan`].
#[derive(Debug, Clone, Default)]
pub struct ScanOutput {
    pub host: Option<PathBuf>,
    pub packages: Option<PathBuf>,
    pub sbom: Option<PathBuf>,
}

/// Scan `options.root` and write one JSON file per asset category under `output_dir`.
pub fn run_static_scan(options: &ScanOptions, output_dir: &Path) -> anyhow::Result<ScanOutput> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create output dir {}", output_dir.display()))?;

    let mut ctx = ScanContext::at(&options.root);
    let mut out = ScanOutput::default();

    for &target in options.target.targets() {
        match target {
            ScanTarget::Host => {
                ensure_host(&mut ctx)?;
                let path = output_dir.join("host.json");
                write_json(&path, ctx.host.as_ref().expect("host set"))?;
                out.host = Some(path);
            }
            ScanTarget::Packages => {
                ensure_host(&mut ctx)?;
                let assets = PackagesCollector.collect(&mut ctx)?;
                let packages = assets_into_packages(assets)?;
                let path = output_dir.join("packages.json");
                write_json(&path, &packages)?;
                out.packages = Some(path);
            }
            ScanTarget::Sbom => {
                let bom = crate::build_sbom(&ctx);
                let path = output_dir.join("sbom.cyclonedx.json");
                write_json(&path, &bom)?;
                out.sbom = Some(path);
            }
            ScanTarget::All => unreachable!("expanded above"),
        }
    }

    Ok(out)
}

fn ensure_host(ctx: &mut ScanContext) -> anyhow::Result<()> {
    if ctx.host.is_some() {
        return Ok(());
    }
    match HostCollector.collect(ctx)? {
        CollectorOutput::Host(host) => {
            ctx.host_id = Some(host.host_id.clone());
            ctx.host = Some(host);
            Ok(())
        }
        _ => anyhow::bail!("host collector returned unexpected output"),
    }
}

fn assets_into_packages(output: CollectorOutput) -> anyhow::Result<Vec<Asset>> {
    match output {
        CollectorOutput::Assets(v) => Ok(v),
        _ => anyhow::bail!("packages collector returned unexpected output"),
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
    let file = fs::File::create(path)
        .with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(file, value)
        .with_context(|| format!("write JSON to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/hostname"), "demo-host\n").unwrap();
        fs::write(
            root.join("etc/os-release"),
            "ID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04\"\n",
        )
        .unwrap();

        fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
        fs::write(
            root.join("var/lib/dpkg/status"),
            "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.2-0ubuntu1.18\n",
        )
        .unwrap();

        temp
    }

    #[test]
    fn sbom_target_writes_cyclonedx_with_purl() {
        let root = fixture_root();
        let out = tempfile::tempdir().unwrap();

        let options = ScanOptions {
            root: root.path().to_path_buf(),
            target: ScanTarget::Sbom,
        };
        let written = run_static_scan(&options, out.path()).unwrap();

        let sbom_path = written.sbom.expect("sbom written");
        assert!(written.host.is_none() && written.packages.is_none());

        let bom: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&sbom_path).unwrap()).unwrap();

        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.6");
        let components = bom["components"].as_array().unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0]["name"], "openssl");
        assert_eq!(
            components[0]["purl"],
            "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04"
        );
        assert_eq!(bom["metadata"]["component"]["type"], "operating-system");
    }

    #[test]
    fn packages_target_includes_language_ecosystems() {
        let root = fixture_root();
        let base = root.path();
        // A Python dist-info and a global npm package alongside the deb status.
        let dist_info = base.join("usr/lib/python3.11/site-packages/requests-2.31.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        fs::write(dist_info.join("METADATA"), "Name: requests\nVersion: 2.31.0\n").unwrap();
        let npm_pkg = base.join("usr/lib/node_modules/lodash");
        fs::create_dir_all(&npm_pkg).unwrap();
        fs::write(
            npm_pkg.join("package.json"),
            r#"{"name":"lodash","version":"4.17.21"}"#,
        )
        .unwrap();

        let out = tempfile::tempdir().unwrap();
        let options = ScanOptions {
            root: base.to_path_buf(),
            target: ScanTarget::Packages,
        };
        let written = run_static_scan(&options, out.path()).unwrap();

        let packages: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(written.packages.unwrap()).unwrap()).unwrap();
        let ecosystems: Vec<&str> = packages
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["ecosystem"].as_str())
            .collect();
        assert!(ecosystems.contains(&"Ubuntu:22.04"), "deb ecosystem missing");
        assert!(ecosystems.contains(&"PyPI"), "PyPI ecosystem missing");
        assert!(ecosystems.contains(&"npm"), "npm ecosystem missing");
    }

    #[test]
    fn all_target_writes_three_files() {
        let root = fixture_root();
        let out = tempfile::tempdir().unwrap();

        let options = ScanOptions {
            root: root.path().to_path_buf(),
            target: ScanTarget::All,
        };
        let written = run_static_scan(&options, out.path()).unwrap();

        assert!(written.host.is_some());
        assert!(written.packages.is_some());
        assert!(written.sbom.is_some());
    }
}
