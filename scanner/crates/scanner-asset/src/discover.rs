//! Auto-discover project roots from marker files under the scan root.
//!
//! When walking the mounted tree we look for `package.json`, `pyproject.toml`,
//! and `requirements.txt`. The directory containing each marker becomes an
//! extra project root for language-package collectors (merged with any
//! explicit `--project-root` flags).

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use scanner_runtime::ScanContext;
use walkdir::WalkDir;

/// Marker filenames that identify a project directory.
const MARKERS: &[&str] = &["package.json", "pyproject.toml", "requirements.txt"];

/// Pseudo-filesystems skipped when auto-discovering under a live root.
const PSEUDO_FS: &[&str] = &["proc", "sys", "dev", "run"];

/// Do not descend into these directory names while discovering markers.
const SKIP_DIR_NAMES: &[&str] = &[
    "node_modules",
    ".git",
    "__pycache__",
    "site-packages",
    "dist-packages",
    ".venv",
    "venv",
    ".tox",
    "target",
    "vendor",
];

/// Max depth from `scan_root` for auto-discovery (keeps full-root scans bounded).
const DISCOVER_MAX_DEPTH: usize = 10;

/// Find project directories under `ctx.scan_root` from marker files.
///
/// Returns paths **relative to** `scan_root`, deduplicated and sorted.
pub fn discover_project_roots(ctx: &ScanContext) -> Vec<PathBuf> {
    let excludes: Vec<PathBuf> = PSEUDO_FS.iter().map(|d| ctx.scan_root.join(d)).collect();

    let mut found = HashSet::new();
    for entry in WalkDir::new(&ctx.scan_root)
        .max_depth(DISCOVER_MAX_DEPTH)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_excluded(e.path(), &excludes))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if !MARKERS.contains(&name.as_ref()) {
            continue;
        }
        if name == "package.json" && path_has_component(entry.path(), OsStr::new("node_modules")) {
            continue;
        }
        let Some(parent) = entry.path().parent() else {
            continue;
        };
        if parent == ctx.scan_root.as_path() {
            found.insert(PathBuf::new());
            continue;
        }
        if let Ok(rel) = parent.strip_prefix(&ctx.scan_root) {
            found.insert(rel.to_path_buf());
        }
    }

    let mut roots: Vec<PathBuf> = found.into_iter().collect();
    roots.sort();
    roots
}

fn is_excluded(path: &Path, excludes: &[PathBuf]) -> bool {
    if excludes.iter().any(|ex| path.starts_with(ex)) {
        return true;
    }
    path.components().any(|c| {
        SKIP_DIR_NAMES
            .iter()
            .any(|skip| c.as_os_str() == OsStr::new(skip))
    })
}

fn path_has_component(path: &Path, name: &OsStr) -> bool {
    path.components().any(|c| c.as_os_str() == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn discovers_pyproject_and_package_json() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("srv/app")).unwrap();
        fs::write(root.join("srv/app/pyproject.toml"), "[project]\n").unwrap();
        fs::create_dir_all(root.join("opt/web")).unwrap();
        fs::write(
            root.join("opt/web/package.json"),
            r#"{"name":"web","version":"1.0.0"}"#,
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let roots = discover_project_roots(&ctx);
        assert_eq!(
            roots,
            vec![PathBuf::from("opt/web"), PathBuf::from("srv/app")]
        );
    }

    #[test]
    fn ignores_package_json_inside_node_modules() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("proj/node_modules/lodash")).unwrap();
        fs::write(
            root.join("proj/node_modules/lodash/package.json"),
            r#"{"name":"lodash","version":"4.0.0"}"#,
        )
        .unwrap();
        fs::write(
            root.join("proj/package.json"),
            r#"{"name":"proj","version":"0.1.0"}"#,
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let roots = discover_project_roots(&ctx);
        assert_eq!(roots, vec![PathBuf::from("proj")]);
    }

    #[test]
    fn discovers_requirements_txt() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("home/user/svc")).unwrap();
        fs::write(root.join("home/user/svc/requirements.txt"), "django\n").unwrap();

        let ctx = ScanContext::at(root);
        let roots = discover_project_roots(&ctx);
        assert_eq!(roots, vec![PathBuf::from("home/user/svc")]);
    }
}
