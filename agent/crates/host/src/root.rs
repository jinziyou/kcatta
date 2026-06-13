//! Path helpers for static scans under a mount root.

use std::path::{Component, Path, PathBuf};

use crate::ScanContext;

/// Resolve `rel` (a `/`-rooted or relative path) under `ctx.scan_root`.
pub fn join_root(ctx: &ScanContext, rel: &str) -> PathBuf {
    let rel = rel.strip_prefix('/').unwrap_or(rel);
    ctx.scan_root.join(rel)
}

/// Like [`join_root`] but for a [`Path`] (e.g. a configured project root).
///
/// Keeps only normal path components, dropping any leading `/`, `.`, `..` or
/// Windows prefix. This contains a configured project root (`--project-root`,
/// operator-supplied) to the mounted image: e.g. `../../etc` resolves under
/// `scan_root`, not the host's real `/etc`.
pub fn join_root_path(ctx: &ScanContext, rel: &Path) -> PathBuf {
    let mut sanitized = PathBuf::new();
    for comp in rel.components() {
        if let Component::Normal(c) = comp {
            sanitized.push(c);
        }
    }
    ctx.scan_root.join(sanitized)
}

/// Read `rel` under `root`, trimmed; `None` if missing or empty after trimming.
pub fn read_trim_at(root: &Path, rel: &str) -> Option<String> {
    let path = root.join(rel.strip_prefix('/').unwrap_or(rel));
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Map an absolute or relative path from source metadata onto `scan_root`.
///
/// Like [`join_root`] (strips a leading `/`), for paths read out of container
/// runtime metadata (Docker `MergedDir`, containerd snapshot `fs`, …).
pub fn resolve_under_root(scan_root: &Path, path: &str) -> PathBuf {
    let path = path.trim();
    if path.is_empty() {
        return scan_root.to_path_buf();
    }
    let rel = path.strip_prefix('/').unwrap_or(path);
    scan_root.join(rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_root_path_contains_parent_dir_escape() {
        let ctx = ScanContext::at("/mnt/image");
        // `..` components must not escape the scan root.
        assert_eq!(
            join_root_path(&ctx, Path::new("../../etc/passwd")),
            PathBuf::from("/mnt/image/etc/passwd")
        );
        // Absolute paths are treated as relative to the scan root.
        assert_eq!(
            join_root_path(&ctx, Path::new("/srv/app")),
            PathBuf::from("/mnt/image/srv/app")
        );
        // Normal relative paths are unchanged.
        assert_eq!(
            join_root_path(&ctx, Path::new("home/user/proj")),
            PathBuf::from("/mnt/image/home/user/proj")
        );
    }
}
