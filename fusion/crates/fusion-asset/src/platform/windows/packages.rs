//! Installed Windows programs: Uninstall registry, WinGet, CBS, and language packages.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use fusion_contract::{Asset, Package};
use fusion_runtime::{ScanContext, WindowsPackageProfile};

use super::distro::WindowsDistro;
use super::paths::first_existing_dir;
use super::registry::{HiveKind, RegistryAccess};
use super::store;
use crate::collectors::packages::collect_language_packages;

const UNINSTALL_PATHS: &[&str] = &[
    r"Microsoft\Windows\CurrentVersion\Uninstall",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
];

const WINGET_REGISTRY: &str = r"Microsoft\WinGet\Packages";
const CBS_PACKAGES: &str = r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages";

/// CBS `CurrentState` value for an installed package.
const CBS_STATE_INSTALLED: &str = "112";

/// Installed programs and language packages as contract [`Asset`]s.
pub fn collect_packages(ctx: &ScanContext) -> Vec<Asset> {
    let reg = RegistryAccess::open(ctx);
    let ecosystem = WindowsDistro::read(&reg).osv_ecosystem();
    let mut seen = HashSet::new();
    let mut assets = collect_uninstall(&reg, ecosystem.clone(), &mut seen);
    assets.extend(collect_winget(&reg, ctx, ecosystem.clone(), &mut seen));
    if matches!(ctx.windows_packages, WindowsPackageProfile::Full) {
        assets.extend(collect_cbs(&reg, ecosystem.clone(), &mut seen));
    }
    let mut push = |asset: Asset| assets.push(asset);
    store::collect_appx(ctx, ecosystem.clone(), &mut seen, &mut push);
    store::collect_chocolatey(ctx, ecosystem, &mut seen, &mut push);
    assets.extend(collect_language_packages(ctx));
    assets
}

fn collect_uninstall(
    reg: &RegistryAccess,
    ecosystem: Option<String>,
    seen: &mut HashSet<(String, String)>,
) -> Vec<Asset> {
    let mut assets = Vec::new();
    for base in UNINSTALL_PATHS {
        for subkey in reg.list_subkeys(HiveKind::Software, base) {
            let path = format!("{base}\\{subkey}");
            let values = reg.read_values(HiveKind::Software, &path);
            let Some(name) = values.get("DisplayName").cloned().filter(|n| !n.is_empty()) else {
                continue;
            };
            if values.get("SystemComponent").is_some_and(|v| v == "1") {
                continue;
            }
            if values.get("ParentKeyName").is_some_and(|v| !v.is_empty()) {
                continue;
            }
            let version = values
                .get("DisplayVersion")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            if !seen.insert((name.clone(), version.clone())) {
                continue;
            }
            let install_path = values
                .get("InstallLocation")
                .cloned()
                .filter(|p| !p.is_empty());
            push_package(
                &mut assets,
                &name,
                &version,
                "windows-uninstall",
                install_path,
                ecosystem.clone(),
            );
        }
    }
    assets.sort_by(|a, b| package_name(a).cmp(package_name(b)));
    assets
}

fn collect_winget(
    reg: &RegistryAccess,
    ctx: &ScanContext,
    ecosystem: Option<String>,
    seen: &mut HashSet<(String, String)>,
) -> Vec<Asset> {
    let mut assets = collect_winget_registry(reg, ecosystem.clone(), seen);
    assets.extend(collect_winget_filesystem(ctx, ecosystem, seen));
    assets
}

fn collect_winget_registry(
    reg: &RegistryAccess,
    ecosystem: Option<String>,
    seen: &mut HashSet<(String, String)>,
) -> Vec<Asset> {
    let mut assets = Vec::new();
    for subkey in reg.list_subkeys(HiveKind::Software, WINGET_REGISTRY) {
        let path = format!("{WINGET_REGISTRY}\\{subkey}");
        let values = reg.read_values(HiveKind::Software, &path);
        let version = values
            .get("Version")
            .cloned()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        let name = winget_id_from_key(&subkey);
        if !seen.insert((name.clone(), version.clone())) {
            continue;
        }
        push_package(
            &mut assets,
            &name,
            &version,
            "windows-winget",
            None,
            ecosystem.clone(),
        );
    }
    assets
}

fn collect_winget_filesystem(
    ctx: &ScanContext,
    ecosystem: Option<String>,
    seen: &mut HashSet<(String, String)>,
) -> Vec<Asset> {
    let Some(root) = first_existing_dir(
        &ctx.scan_root,
        &[&["ProgramData", "Microsoft", "WinGet", "Packages"]],
    ) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut assets = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let key = entry.file_name().to_string_lossy().into_owned();
        let name = winget_id_from_key(&key);
        let version =
            read_winget_version_file(&entry.path()).unwrap_or_else(|| "unknown".to_string());
        if !seen.insert((name.clone(), version.clone())) {
            continue;
        }
        push_package(
            &mut assets,
            &name,
            &version,
            "windows-winget",
            Some(entry.path().display().to_string()),
            ecosystem.clone(),
        );
    }
    assets
}

fn read_winget_version_file(dir: &Path) -> Option<String> {
    for name in ["version.txt", "VERSION"] {
        let path = dir.join(name);
        if let Ok(text) = fs::read_to_string(&path) {
            let v = text.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn winget_id_from_key(key: &str) -> String {
    key.rsplit_once('_')
        .map(|(id, _)| id.to_string())
        .unwrap_or_else(|| key.to_string())
}

fn collect_cbs(
    reg: &RegistryAccess,
    ecosystem: Option<String>,
    seen: &mut HashSet<(String, String)>,
) -> Vec<Asset> {
    let mut assets = Vec::new();
    for subkey in reg.list_subkeys(HiveKind::Software, CBS_PACKAGES) {
        let path = format!("{CBS_PACKAGES}\\{subkey}");
        let values = reg.read_values(HiveKind::Software, &path);
        if values
            .get("CurrentState")
            .is_some_and(|s| s != CBS_STATE_INSTALLED)
        {
            continue;
        }
        let version = values
            .get("Version")
            .cloned()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        let name = cbs_display_name(&subkey, &values);
        if !seen.insert((name.clone(), version.clone())) {
            continue;
        }
        push_package(
            &mut assets,
            &name,
            &version,
            "windows-cbs",
            None,
            ecosystem.clone(),
        );
    }
    assets
}

fn cbs_display_name(key: &str, values: &std::collections::HashMap<String, String>) -> String {
    values
        .get("InstallName")
        .cloned()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| key.to_string())
}

pub(crate) fn make_package(
    name: &str,
    version: &str,
    source: &str,
    install_path: Option<String>,
    ecosystem: Option<String>,
) -> Asset {
    let slug = slugify(name);
    Asset::Package(Package {
        asset_id: format!("pkg-{slug}-{version}"),
        name: name.to_string(),
        version: version.to_string(),
        source: Some(source.to_string()),
        install_path,
        ecosystem,
    })
}

fn push_package(
    assets: &mut Vec<Asset>,
    name: &str,
    version: &str,
    source: &str,
    install_path: Option<String>,
    ecosystem: Option<String>,
) {
    assets.push(make_package(name, version, source, install_path, ecosystem));
}

fn package_name(asset: &Asset) -> &str {
    match asset {
        Asset::Package(p) => &p.name,
        _ => "",
    }
}

fn slugify(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winget_id_strips_source_hash_suffix() {
        assert_eq!(
            winget_id_from_key("Microsoft.WindowsTerminal_8wekyb3d8bbwe"),
            "Microsoft.WindowsTerminal"
        );
    }
}
