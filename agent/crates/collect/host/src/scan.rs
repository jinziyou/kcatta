//! Static filesystem scan API: mount root + target → per-asset JSON files.
//!
//! Companion to [`crate::run_scan_at`] (merged [`agent_contract::AssetReport`]).
//! See the dual-API note on [`crate::scan_runner`].

use std::fs;
use std::path::{Path, PathBuf};

use crate::{Collector, CollectorOutput, ScanContext, WindowsPackageProfile};
use anyhow::Context;

use crate::collectors::{
    collect_accounts, collect_credentials, collect_packages, collect_services, DebPackage,
    HostCollector,
};

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
    /// `host.json`, `packages.json`, `sbom.cyclonedx.json`, and identity files.
    All,
    /// `services.json` only.
    Services,
    /// `accounts.json` only.
    Accounts,
    /// `credentials.json` only.
    Credentials,
    /// `services.json`, `accounts.json`, and `credentials.json`.
    Identity,
}

impl ScanTarget {
    /// Parse CLI target strings (`host`, `all`, `packages`, …).
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "packages" | "package" => Ok(Self::Packages),
            "sbom" | "cyclonedx" => Ok(Self::Sbom),
            "services" | "service" => Ok(Self::Services),
            "accounts" | "account" => Ok(Self::Accounts),
            "credentials" | "credential" => Ok(Self::Credentials),
            "identity" => Ok(Self::Identity),
            "all" => Ok(Self::All),
            "ports" | "port" => anyhow::bail!(
                "port scanning is already included in host reports; use host|packages|sbom|services|accounts|credentials|identity|all"
            ),
            other => {
                anyhow::bail!(
                    "unknown scan target {other:?} (use host|packages|sbom|services|accounts|credentials|identity|all)"
                )
            }
        }
    }

    fn targets(self) -> &'static [ScanTarget] {
        match self {
            Self::Host => &[Self::Host],
            Self::Packages => &[Self::Packages],
            Self::Sbom => &[Self::Sbom],
            Self::Services => &[Self::Services],
            Self::Accounts => &[Self::Accounts],
            Self::Credentials => &[Self::Credentials],
            Self::Identity => &[Self::Services, Self::Accounts, Self::Credentials],
            Self::All => &[Self::All],
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
    /// Extra project directories (relative to `root`) to scan for language
    /// packages beyond global install locations (venvs, project node_modules).
    pub project_roots: Vec<PathBuf>,
    /// Windows-only: CBS update packages (`full`) or user apps only (`apps`).
    pub windows_packages: WindowsPackageProfile,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            target: ScanTarget::Host,
            project_roots: Vec::new(),
            windows_packages: WindowsPackageProfile::default(),
        }
    }
}

/// Paths of JSON files written by [`run_static_scan`].
#[derive(Debug, Clone, Default)]
pub struct ScanOutput {
    /// Path to `host.json` when written.
    pub host: Option<PathBuf>,
    /// Path to `packages.json` when written.
    pub packages: Option<PathBuf>,
    /// Path to `sbom.cyclonedx.json` when written.
    pub sbom: Option<PathBuf>,
    /// Path to `services.json` when written.
    pub services: Option<PathBuf>,
    /// Path to `accounts.json` when written.
    pub accounts: Option<PathBuf>,
    /// Path to `credentials.json` when written.
    pub credentials: Option<PathBuf>,
}

impl ScanOutput {
    /// All written paths in stable order (host → packages → sbom → services → accounts → credentials).
    pub fn written_paths(&self) -> impl Iterator<Item = &PathBuf> {
        [
            &self.host,
            &self.packages,
            &self.sbom,
            &self.services,
            &self.accounts,
            &self.credentials,
        ]
        .into_iter()
        .flatten()
    }
}

/// Scan `options.root` and write one JSON file per asset category under `output_dir`.
///
/// Returns paths of every file written; use [`ScanOutput::written_paths`] to iterate.
pub fn run_static_scan(options: &ScanOptions, output_dir: &Path) -> anyhow::Result<ScanOutput> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create output dir {}", output_dir.display()))?;

    let mut ctx = ScanContext::at(&options.root)
        .with_project_roots(options.project_roots.clone())
        .with_windows_packages(options.windows_packages);
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
                let packages = collect_packages(&mut ctx, None);
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
            ScanTarget::Services => {
                ensure_host(&mut ctx)?;
                let path = output_dir.join("services.json");
                write_json(&path, &collect_services(&ctx))?;
                out.services = Some(path);
            }
            ScanTarget::Accounts => {
                ensure_host(&mut ctx)?;
                let path = output_dir.join("accounts.json");
                write_json(&path, &collect_accounts(&ctx))?;
                out.accounts = Some(path);
            }
            ScanTarget::Credentials => {
                ensure_host(&mut ctx)?;
                let path = output_dir.join("credentials.json");
                write_json(&path, &collect_credentials(&ctx))?;
                out.credentials = Some(path);
            }
            ScanTarget::Identity => {
                ensure_host(&mut ctx)?;
                let services_path = output_dir.join("services.json");
                write_json(&services_path, &collect_services(&ctx))?;
                out.services = Some(services_path);

                let accounts_path = output_dir.join("accounts.json");
                write_json(&accounts_path, &collect_accounts(&ctx))?;
                out.accounts = Some(accounts_path);

                let credentials_path = output_dir.join("credentials.json");
                write_json(&credentials_path, &collect_credentials(&ctx))?;
                out.credentials = Some(credentials_path);
            }
            ScanTarget::All => {
                ensure_host(&mut ctx)?;
                let path = output_dir.join("host.json");
                write_json(&path, ctx.host.as_ref().expect("host set"))?;
                out.host = Some(path);

                let mut deb_cache: Option<Vec<DebPackage>> = None;
                let packages = collect_packages(&mut ctx, Some(&mut deb_cache));
                let packages_path = output_dir.join("packages.json");
                write_json(&packages_path, &packages)?;
                out.packages = Some(packages_path);

                let deb_pkgs = deb_cache.as_deref().unwrap_or(&[]);
                let bom = crate::build_sbom_from_assets(ctx.clone(), &packages, Some(deb_pkgs));
                let sbom_path = output_dir.join("sbom.cyclonedx.json");
                write_json(&sbom_path, &bom)?;
                out.sbom = Some(sbom_path);

                let services_path = output_dir.join("services.json");
                write_json(&services_path, &collect_services(&ctx))?;
                out.services = Some(services_path);

                let accounts_path = output_dir.join("accounts.json");
                write_json(&accounts_path, &collect_accounts(&ctx))?;
                out.accounts = Some(accounts_path);

                let credentials_path = output_dir.join("credentials.json");
                write_json(&credentials_path, &collect_credentials(&ctx))?;
                out.credentials = Some(credentials_path);
                break;
            }
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

fn write_json(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
    let file = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
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
            ..Default::default()
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
        fs::write(
            dist_info.join("METADATA"),
            "Name: requests\nVersion: 2.31.0\n",
        )
        .unwrap();
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
            ..Default::default()
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
        assert!(
            ecosystems.contains(&"Ubuntu:22.04"),
            "deb ecosystem missing"
        );
        assert!(ecosystems.contains(&"PyPI"), "PyPI ecosystem missing");
        assert!(ecosystems.contains(&"npm"), "npm ecosystem missing");
    }

    #[test]
    fn sbom_includes_language_package_purls() {
        let root = fixture_root();
        let base = root.path();
        let dist_info = base.join("usr/lib/python3.11/site-packages/requests-2.31.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        fs::write(
            dist_info.join("METADATA"),
            "Name: requests\nVersion: 2.31.0\n",
        )
        .unwrap();
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
            target: ScanTarget::Sbom,
            ..Default::default()
        };
        let written = run_static_scan(&options, out.path()).unwrap();
        let bom: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(written.sbom.unwrap()).unwrap()).unwrap();
        let purls: Vec<&str> = bom["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["purl"].as_str())
            .collect();
        assert!(purls.iter().any(|p| p.contains("pkg:deb/")));
        assert!(purls.contains(&"pkg:pypi/requests@2.31.0"));
        assert!(purls.contains(&"pkg:npm/lodash@4.17.21"));
    }

    #[test]
    fn windows_host_target_without_registry_fallback() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("windows/System32")).unwrap();
        fs::write(temp.path().join("windows/System32/ntoskrnl.exe"), b"").unwrap();

        let out = tempfile::tempdir().unwrap();
        let options = ScanOptions {
            root: temp.path().to_path_buf(),
            target: ScanTarget::Host,
            ..Default::default()
        };
        let written = run_static_scan(&options, out.path()).unwrap();
        let host: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(written.host.unwrap()).unwrap()).unwrap();
        assert_eq!(host["hostname"], "unknown-host");
        assert!(host["os"].as_str().unwrap().contains("Windows"));
    }

    #[test]
    fn all_target_writes_six_files() {
        let root = fixture_root();
        let out = tempfile::tempdir().unwrap();

        let options = ScanOptions {
            root: root.path().to_path_buf(),
            target: ScanTarget::All,
            ..Default::default()
        };
        let written = run_static_scan(&options, out.path()).unwrap();

        assert!(written.host.is_some());
        assert!(written.packages.is_some());
        assert!(written.sbom.is_some());
        assert!(written.services.is_some());
        assert!(written.accounts.is_some());
        assert!(written.credentials.is_some());
    }
}
