//! CycloneDX SBOM export.
//!
//! Turns the dpkg package inventory under a scan root into a CycloneDX 1.6
//! JSON document with one `library` component per package, each carrying a
//! Package URL (`purl`). The output is consumable as-is by `trivy sbom`,
//! which keys CVE matching off the `purl`.

use serde::Serialize;

use scanner_runtime::ScanContext;

use crate::collectors::{deb_packages, DebPackage};
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
}

/// Build a CycloneDX BOM from the packages under `ctx.scan_root`.
pub fn build_sbom(ctx: &ScanContext) -> Bom {
    let distro = read_distro(ctx);
    let components = deb_packages(ctx)
        .iter()
        .map(|pkg| package_component(pkg, &distro))
        .collect();

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

fn package_component(pkg: &DebPackage, distro: &Distro) -> Component {
    let purl = deb_purl(pkg, distro);
    Component {
        bom_ref: Some(purl.clone()),
        component_type: "library".to_string(),
        name: pkg.name.clone(),
        version: Some(pkg.version.clone()),
        purl: Some(purl),
    }
}

fn os_component(distro: &Distro) -> Option<Component> {
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

fn read_distro(ctx: &ScanContext) -> Distro {
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
            "pkg:deb/debian/bash@5.1?arch=arm64"
        );
    }

    #[test]
    fn parses_os_release_id() {
        let line_id = parse_kv("ID=ubuntu", "ID");
        let line_quoted = parse_kv("VERSION_ID=\"22.04\"", "VERSION_ID");
        assert_eq!(line_id.as_deref(), Some("ubuntu"));
        assert_eq!(line_quoted.as_deref(), Some("22.04"));
        // Prefix must be followed by '='; ID_LIKE must not match ID.
        assert_eq!(parse_kv("ID_LIKE=debian", "ID"), None);
    }
}
