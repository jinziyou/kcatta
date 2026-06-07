//! Windows directory layout helpers under a scan root.

use std::path::{Path, PathBuf};

use fusion_runtime::ScanContext;

use crate::platform::find_path_case_insensitive;

/// `Windows/System32/config` (offline registry hive directory).
pub fn config_dir(ctx: &ScanContext) -> Option<PathBuf> {
    find_path_case_insensitive(&ctx.scan_root, &["Windows", "System32", "config"])
}

/// `Users` profile directory.
pub fn users_dir(ctx: &ScanContext) -> Option<PathBuf> {
    find_path_case_insensitive(&ctx.scan_root, &["Users"])
}

/// Find the first existing directory among `candidates` (case-insensitive segments).
pub fn first_existing_dir(root: &Path, candidates: &[&[&str]]) -> Option<PathBuf> {
    candidates
        .iter()
        .find_map(|parts| find_path_case_insensitive(root, parts))
        .filter(|p| p.is_dir())
}
