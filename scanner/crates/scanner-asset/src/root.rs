//! Path helpers for static scans under a mount root.

use std::path::{Path, PathBuf};

use scanner_runtime::ScanContext;

pub fn join_root(ctx: &ScanContext, rel: &str) -> PathBuf {
    let rel = rel.strip_prefix('/').unwrap_or(rel);
    ctx.scan_root.join(rel)
}

pub fn read_trim_at(root: &Path, rel: &str) -> Option<String> {
    let path = root.join(rel.strip_prefix('/').unwrap_or(rel));
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
