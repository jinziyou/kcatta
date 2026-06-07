//! AppX (Microsoft Store) and Chocolatey package inventories.

use std::collections::HashSet;
use std::fs;

use crate::ScanContext;
use fusion_contract::Asset;

use super::packages::make_package;
use super::paths::first_existing_dir;

/// Parse a `WindowsApps` directory name into `(name, version)`.
pub fn parse_windows_apps_dir(name: &str) -> Option<(String, String)> {
    let base = name.split("__").next()?;
    let (rest, arch) = base.rsplit_once('_')?;
    if !matches!(arch, "x64" | "x86" | "arm" | "arm64" | "neutral") {
        return None;
    }
    let (pkg_name, version) = rest.rsplit_once('_')?;
    if pkg_name.is_empty() || version.is_empty() {
        return None;
    }
    Some((pkg_name.to_string(), version.to_string()))
}

/// Push AppX / Microsoft Store packages from `Program Files\WindowsApps`,
/// deduplicated against `seen` by `(name, version)`.
pub fn collect_appx(
    ctx: &ScanContext,
    ecosystem: Option<String>,
    seen: &mut HashSet<(String, String)>,
    push: &mut dyn FnMut(Asset),
) {
    let Some(root) = first_existing_dir(&ctx.scan_root, &[&["Program Files", "WindowsApps"]])
    else {
        return;
    };
    let Ok(entries) = fs::read_dir(&root) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().into_owned();
        let Some((name, version)) = parse_windows_apps_dir(&dir_name) else {
            continue;
        };
        if !seen.insert((name.clone(), version.clone())) {
            continue;
        }
        push(make_package(
            &name,
            &version,
            "windows-appx",
            Some(entry.path().display().to_string()),
            ecosystem.clone(),
        ));
    }
}

/// Push Chocolatey packages from `ProgramData\chocolatey\lib` (versions read
/// from each `.nuspec`), deduplicated against `seen` by `(name, version)`.
pub fn collect_chocolatey(
    ctx: &ScanContext,
    ecosystem: Option<String>,
    seen: &mut HashSet<(String, String)>,
    push: &mut dyn FnMut(Asset),
) {
    let Some(root) = first_existing_dir(&ctx.scan_root, &[&["ProgramData", "chocolatey", "lib"]])
    else {
        return;
    };
    let Ok(entries) = fs::read_dir(&root) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let nuspec = entry.path().join(format!("{name}.nuspec"));
        let Some(version) = read_nuspec_version(&nuspec) else {
            continue;
        };
        if !seen.insert((name.clone(), version.clone())) {
            continue;
        }
        push(make_package(
            &name,
            &version,
            "windows-chocolatey",
            Some(entry.path().display().to_string()),
            ecosystem.clone(),
        ));
    }
}

fn read_nuspec_version(path: &std::path::Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    extract_xml_tag(&text, "version")
}

fn extract_xml_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    let value = text[start..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_apps_folder() {
        let (name, version) =
            parse_windows_apps_dir("Microsoft.WindowsTerminal_1.21.2701.0_x64__8wekyb3d8bbwe")
                .unwrap();
        assert_eq!(name, "Microsoft.WindowsTerminal");
        assert_eq!(version, "1.21.2701.0");
    }

    #[test]
    fn reads_nuspec_version_tag() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("curl.nuspec");
        fs::write(
            &path,
            r#"<?xml version="1.0"?><package><metadata><version>8.7.1</version></metadata></package>"#,
        )
        .unwrap();
        assert_eq!(read_nuspec_version(&path).as_deref(), Some("8.7.1"));
    }
}
