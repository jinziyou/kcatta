//! Auto-discover project roots from marker files under the scan root.
//!
//! When walking the mounted tree we look for `package.json`, `pyproject.toml`,
//! and `requirements.txt`. The directory containing each marker becomes an
//! extra project root for language-package collectors (merged with any
//! explicit `--project-root` flags).

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::PathBuf;

use probe_runtime::ScanContext;

use super::engine::{walk, WalkConfig};
use super::policy::{path_has_component, PSEUDO_FS};

/// Marker filenames that identify a project directory.
const MARKERS: &[&str] = &["package.json", "pyproject.toml", "requirements.txt"];

/// Max depth from `scan_root` for auto-discovery (keeps full-root scans bounded).
const DISCOVER_MAX_DEPTH: usize = 10;

/// Find project directories under `ctx.scan_root` from marker files.
///
/// Returns paths **relative to** `scan_root`, deduplicated and sorted.
pub fn discover_project_roots(ctx: &ScanContext) -> Vec<PathBuf> {
    let excludes: Vec<PathBuf> = PSEUDO_FS.iter().map(|d| ctx.scan_root.join(d)).collect();
    let config = WalkConfig::at(&ctx.scan_root, DISCOVER_MAX_DEPTH)
        .with_subtree_excludes(excludes)
        .with_dir_skip_policy();

    let mut found = HashSet::new();
    walk(&config, |entry| {
        if !entry.file_type().is_file() {
            return;
        }
        let name = entry.file_name().to_string_lossy();
        if !MARKERS.contains(&name.as_ref()) {
            return;
        }
        if name == "package.json" && path_has_component(entry.path(), OsStr::new("node_modules")) {
            return;
        }
        let Some(parent) = entry.path().parent() else {
            return;
        };
        if parent == ctx.scan_root.as_path() {
            found.insert(PathBuf::new());
            return;
        }
        if let Ok(rel) = parent.strip_prefix(&ctx.scan_root) {
            found.insert(rel.to_path_buf());
        }
    });

    let mut roots: Vec<PathBuf> = found.into_iter().collect();
    roots.sort();
    roots
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

    #[test]
    fn skips_windows_system_dirs_when_scanning_mount() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("windows/System32")).unwrap();
        fs::write(root.join("windows/System32/ntoskrnl.exe"), b"").unwrap();
        fs::create_dir_all(root.join("Users/alice/project")).unwrap();
        fs::write(
            root.join("Users/alice/project/pyproject.toml"),
            "[project]\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("Program Files/vendor/app")).unwrap();
        fs::write(
            root.join("Program Files/vendor/app/package.json"),
            r#"{"name":"skip","version":"1.0.0"}"#,
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let roots = discover_project_roots(&ctx);
        assert_eq!(roots, vec![PathBuf::from("Users/alice/project")]);
    }
}
