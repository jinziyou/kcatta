//! PyPI project-root walk handler: `*.dist-info` / `*.egg-info` metadata.

use std::fs;
use std::path::Path;

use walkdir::DirEntry;

/// Match Python distribution metadata directories during a project walk.
pub fn matches(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    name.ends_with(".dist-info") || name.ends_with(".egg-info")
}

/// Extract `(name, version)` from a matched metadata directory.
pub fn extract(entry: &DirEntry) -> Option<(String, String)> {
    let name = entry.file_name().to_string_lossy();
    let metadata_file = if name.ends_with(".dist-info") {
        entry.path().join("METADATA")
    } else {
        entry.path().join("PKG-INFO")
    };
    parse_metadata(&metadata_file)
}

/// Pull `Name` / `Version` from an RFC822-style METADATA / PKG-INFO header.
pub fn parse_metadata(path: &Path) -> Option<(String, String)> {
    let text = fs::read_to_string(path).ok()?;
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(v) = line.strip_prefix("Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
    }
    let (name, version) = (name?, version?);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((normalize_name(&name), version))
}

/// PEP 503 normalisation: lowercase and collapse runs of `-`, `_`, `.` to a
/// single `-`. OSV keys PyPI advisories by this normalised form.
pub fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.extend(ch.to_lowercase());
            prev_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_pep503() {
        assert_eq!(normalize_name("Flask"), "flask");
        assert_eq!(normalize_name("ruamel.yaml"), "ruamel-yaml");
        assert_eq!(normalize_name("typing_extensions"), "typing-extensions");
        assert_eq!(normalize_name("Foo--_.Bar"), "foo-bar");
    }
}
