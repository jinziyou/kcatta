//! CycloneDX SBOM export.
//!
//! Builds a CycloneDX 1.6 JSON document with one `library` component per
//! installed package (dpkg, apk, rpm, PyPI, npm), each carrying a Package URL
//! (`purl`). The output is consumable as-is by `trivy sbom`, which keys CVE
//! matching off the `purl`.

use std::collections::HashMap;

use scanner_contract::{Asset, Package};
use serde::Serialize;

use scanner_runtime::ScanContext;

use crate::collectors::{collect_packages, deb_packages, DebPackage};
use crate::root::join_root;

const SPEC_VERSION: &str = "1.6";

/// A CycloneDX bill of materials.
#[derive(Debug, Clone, Serialize)]
pub struct Bom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    pub components: Vec<Component>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Metadata {
    pub timestamp: String,
    pub tools: Vec<Tool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<Component>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Component {
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

/// OS identity used as the deb purl namespace + `distro` qualifier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Distro {
    pub id: Option<String>,
    pub version_id: Option<String>,
}

impl Distro {
    /// purl namespace; deb purls require one, so fall back to `debian`.
    fn namespace(&self) -> &str {
        self.id.as_deref().unwrap_or("debian")
    }

    /// `distro` qualifier value, e.g. `ubuntu-22.04`, when both parts are known.
    fn qualifier(&self) -> Option<String> {
        match (&self.id, &self.version_id) {
            (Some(id), Some(ver)) => Some(format!("{id}-{ver}")),
            _ => None,
        }
    }

    /// OSV ecosystem string for vulnerability matching, e.g. `Debian:12` or
    /// `Ubuntu:22.04`. Returns `None` for distros OSV does not track here
    /// (callers then leave `Package.ecosystem` unset and fall back to the
    /// host-derived ecosystem in `form`).
    pub fn osv_ecosystem(&self) -> Option<String> {
        let version = self.version_id.as_deref()?;
        match self.id.as_deref()? {
            "debian" => Some(format!("Debian:{version}")),
            "ubuntu" => Some(format!("Ubuntu:{version}")),
            "alpine" => {
                // OSV keys Alpine by the `v<major>.<minor>` branch, e.g.
                // VERSION_ID "3.18.4" -> "Alpine:v3.18".
                let branch = version.split('.').take(2).collect::<Vec<_>>().join(".");
                Some(format!("Alpine:v{branch}"))
            }
            // RPM distros: OSV keys these by the major version only,
            // e.g. VERSION_ID "9.3" -> "Rocky Linux:9".
            "rocky" => Some(format!("Rocky Linux:{}", major(version))),
            "almalinux" => Some(format!("AlmaLinux:{}", major(version))),
            _ => None,
        }
    }
}

/// First dot-separated component of a version string (the major release).
fn major(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

/// Build a CycloneDX BOM from all package inventories under `ctx.scan_root`.
pub fn build_sbom(ctx: &ScanContext) -> Bom {
    let mut ctx = ctx.clone();
    let packages = collect_packages(&mut ctx, None);
    build_sbom_from_assets(ctx, &packages, None)
}

/// Build a CycloneDX BOM from pre-parsed dpkg packages (deb-only legacy helper).
pub fn build_sbom_from_debs(ctx: &ScanContext, packages: &[DebPackage]) -> Bom {
    let distro = read_distro(ctx);
    let components = packages
        .iter()
        .map(|pkg| package_component(pkg, &distro))
        .collect();
    bom_shell(ctx, components)
}

/// Build a CycloneDX BOM from collected package assets across all ecosystems.
///
/// When `deb_cache` is supplied, dpkg purls include `arch` without re-reading
/// `var/lib/dpkg/status`.
pub fn build_sbom_from_assets(
    ctx: ScanContext,
    assets: &[Asset],
    deb_cache: Option<&[DebPackage]>,
) -> Bom {
    let distro = read_distro(&ctx);
    let deb_by_name: HashMap<&str, &DebPackage> = match deb_cache {
        Some(pkgs) => pkgs.iter().map(|p| (p.name.as_str(), p)).collect(),
        None => deb_packages(&ctx)
            .iter()
            .map(|p| (p.name.as_str(), p))
            .collect(),
    };

    let mut components = Vec::new();
    for asset in assets {
        let Asset::Package(pkg) = asset else {
            continue;
        };
        if let Some(component) = asset_component(pkg, &distro, &deb_by_name) {
            components.push(component);
        }
    }
    bom_shell(&ctx, components)
}

fn bom_shell(ctx: &ScanContext, components: Vec<Component>) -> Bom {
    let distro = read_distro(ctx);
    Bom {
        bom_format: "CycloneDX".to_string(),
        spec_version: SPEC_VERSION.to_string(),
        serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        version: 1,
        metadata: Metadata {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tools: vec![Tool {
                vendor: "cyber-posture".to_string(),
                name: "scanner-asset".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            }],
            component: os_component(&distro),
        },
        components,
    }
}

fn asset_component(
    pkg: &Package,
    distro: &Distro,
    deb_by_name: &HashMap<&str, &DebPackage>,
) -> Option<Component> {
    let purl = match pkg.source.as_deref()? {
        "dpkg" => deb_by_name
            .get(pkg.name.as_str())
            .map(|deb| deb_purl(deb, distro)),
        "apk" => Some(apk_purl(&pkg.name, &pkg.version, distro)),
        "rpm" => Some(rpm_purl(&pkg.name, &pkg.version, distro)),
        "pip" => Some(pypi_purl(&pkg.name, &pkg.version)),
        "npm" => Some(npm_purl(&pkg.name, &pkg.version)),
        _ => None,
    }?;
    Some(Component {
        bom_ref: Some(purl.clone()),
        component_type: "library".to_string(),
        name: pkg.name.clone(),
        version: Some(pkg.version.clone()),
        purl: Some(purl),
    })
}

/// Build a deb Package URL: `pkg:deb/<distro>/<name>@<version>?arch=&distro=`.
fn deb_purl(pkg: &DebPackage, distro: &Distro) -> String {
    let id = distro.id.as_ref()?;
    Some(Component {
        bom_ref: Some(format!("os:{id}")),
        component_type: "operating-system".to_string(),
        name: id.clone(),
        version: distro.version_id.clone(),
        purl: None,
    })
}

/// Build a deb Package URL: `pkg:deb/<distro>/<name>@<version>?arch=&distro=`.
fn deb_purl(pkg: &DebPackage, distro: &Distro) -> String {
    let mut purl = format!(
        "pkg:deb/{}/{}@{}",
        encode(distro.namespace()),
        encode(&pkg.name),
        encode(&pkg.version),
    );

    let mut qualifiers = Vec::new();
    if let Some(arch) = &pkg.arch {
        qualifiers.push(format!("arch={}", encode(arch)));
    }
    if let Some(q) = distro.qualifier() {
        qualifiers.push(format!("distro={}", encode(&q)));
    }
    if !qualifiers.is_empty() {
        purl.push('?');
        purl.push_str(&qualifiers.join("&"));
    }
    purl
}

/// Percent-encode everything outside the purl unreserved set
/// (`A-Z a-z 0-9 - . _ ~`). Decoding (e.g. by trivy) restores the original.
fn encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

pub(crate) fn read_distro(ctx: &ScanContext) -> Distro {
    let path = join_root(ctx, "etc/os-release");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Distro::default();
    };
    let mut distro = Distro::default();
    for line in text.lines() {
        if let Some(v) = parse_kv(line, "ID") {
            distro.id = Some(v);
        } else if let Some(v) = parse_kv(line, "VERSION_ID") {
            distro.version_id = Some(v);
        }
    }
    distro
}

fn parse_kv(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?.strip_prefix('=')?;
    let value = rest.trim().trim_matches('"').to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ubuntu() -> Distro {
        Distro {
            id: Some("ubuntu".to_string()),
            version_id: Some("22.04".to_string()),
        }
    }

    #[test]
    fn purl_includes_arch_and_distro() {
        let pkg = DebPackage {
            name: "openssl".to_string(),
            version: "3.0.2-0ubuntu1.18".to_string(),
            arch: Some("amd64".to_string()),
        };
        assert_eq!(
            deb_purl(&pkg, &ubuntu()),
            "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04"
        );
    }

    #[test]
    fn purl_encodes_epoch_and_plus() {
        let pkg = DebPackage {
            name: "libstdc++6".to_string(),
            version: "2:12.1.0".to_string(),
            arch: None,
        };
        // ':' -> %3A, '+' -> %2B; no arch qualifier when arch is None.
        assert_eq!(
            deb_purl(&pkg, &ubuntu()),
            "pkg:deb/ubuntu/libstdc%2B%2B6@2%3A12.1.0?distro=ubuntu-22.04"
        );
    }

    #[test]
    fn purl_falls_back_to_debian_namespace() {
        let pkg = DebPackage {
            name: "bash".to_string(),
            version: "5.1".to_string(),
            arch: Some("arm64".to_string()),
        };
        assert_eq!(
            deb_purl(&pkg, &Distro::default()),
      