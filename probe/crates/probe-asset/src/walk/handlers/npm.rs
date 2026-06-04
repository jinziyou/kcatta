//! npm project-root walk handler: `package.json` under `node_modules`.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use walkdir::DirEntry;

/// Match installed npm package manifests during a project walk.
pub fn matches(entry: &DirEntry) -> bool {
    if entry.file_name() != OsStr::new("package.json") || !entry.file_type().is_file() {
        return false;
    }
    entry
        .path()
        .components()
        .any(|c| c.as_os_str() == OsStr::new("node_modules"))
}

/// Extract `(name, version)` from a matched `package.json`.
pub fn extract(entry: &DirEntry) -> Option<(String, String)> {
    parse_package_json(entry.path())
}

/// Read `name` and `version` from a `package.json`; `None` if either is missing or empty.
pub fn parse_package_json(path: &Path) -> Option<(String, String)> {
    let text = fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let name = value.get("name")?.as_str()?.to_string();
    let version = value.get("version")?.as_str()?.to_string();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}
