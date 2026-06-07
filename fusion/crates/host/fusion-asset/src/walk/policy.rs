//! Shared skip/exclude rules for bounded filesystem walks.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Pseudo-filesystems skipped when walking under a live Linux root.
pub const PSEUDO_FS: &[&str] = &["proc", "sys", "dev", "run"];

/// Directory names that prune an entire subtree during policy-aware walks.
pub const SKIP_DIR_NAMES: &[&str] = &[
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

/// Windows system trees skipped during policy-aware walks (case-insensitive).
pub const WINDOWS_SKIP_DIR_NAMES: &[&str] = &[
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "$Recycle.Bin",
    "AppData",
    "WinSxS",
];

/// Whether `path` lies under an excluded subtree or contains a skipped directory component.
pub fn is_excluded(path: &Path, subtree_excludes: &[PathBuf]) -> bool {
    if subtree_excludes.iter().any(|ex| path.starts_with(ex)) {
        return true;
    }
    path.components().any(|c| {
        let name = c.as_os_str();
        SKIP_DIR_NAMES.iter().any(|skip| name == OsStr::new(skip))
            || WINDOWS_SKIP_DIR_NAMES
                .iter()
                .any(|skip| name.eq_ignore_ascii_case(OsStr::new(skip)))
    })
}

/// Whether any path component equals `name`.
pub fn path_has_component(path: &Path, name: &OsStr) -> bool {
    path.components().any(|c| c.as_os_str() == name)
}
