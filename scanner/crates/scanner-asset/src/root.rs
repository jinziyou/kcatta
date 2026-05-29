//! Path helpers for static scans under a mount root.

use std::path::{Path, PathBuf};

use scanner_runtime::ScanContext;

pub fn join_root(ctx: &ScanContext, rel: &str) -> PathBuf {
    let rel = rel.strip_prefix('/').unwrap_or(rel);
    ctx.scan_root.join(rel)
}

/// Like [`join_root`] but for a [`Path`] (e.g. a configured project root).
/// An absolute `rel` is treated as relative to `scan_root`.
pub fn join_root_path(ctx: &ScanContext, rel: &Path) -> PathBuf {
    let rel = rel.strip_prefix("/").unwrap_or(rel);
    ctx.scan_root.join(rel)
}

pub fn read_trim_at(root: &Path, rel: &str) -> Option<String> {
    let path = root.join(rel.strip_prefix('/').unwrap_or(rel));
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
