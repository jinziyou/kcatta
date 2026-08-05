//! Unified bounded WalkDir wrapper for static asset discovery.

use std::fs;
use std::path::{Path, PathBuf};

use walkdir::DirEntry;
use walkdir::WalkDir;

use super::policy;

/// Parameters for a bounded filesystem walk.
#[derive(Debug, Clone)]
pub struct WalkConfig {
    /// Root directory to walk.
    pub root: PathBuf,
    /// Maximum depth relative to `root`.
    pub max_depth: usize,
    /// Whether to follow symbolic links.
    pub follow_links: bool,
    /// Entire subtrees under these paths are skipped.
    pub subtree_excludes: Vec<PathBuf>,
    /// When true, prune dirs matching [`policy::SKIP_DIR_NAMES`] and Windows skips.
    pub apply_dir_skip_policy: bool,
}

impl WalkConfig {
    /// Walk `root` up to `max_depth` without link following or skip policy.
    pub fn at(root: impl Into<PathBuf>, max_depth: usize) -> Self {
        Self {
            root: root.into(),
            max_depth,
            follow_links: false,
            subtree_excludes: Vec::new(),
            apply_dir_skip_policy: false,
        }
    }

    /// Skip the given subtrees entirely during the walk.
    pub fn with_subtree_excludes(mut self, excludes: Vec<PathBuf>) -> Self {
        self.subtree_excludes = excludes;
        self
    }

    /// Enable pruning of directories matching the shared dir-skip policy.
    pub fn with_dir_skip_policy(mut self) -> Self {
        self.apply_dir_skip_policy = true;
        self
    }
}

/// Diagnostics emitted by the same bounded walk that produced inventory rows.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WalkDiagnostics {
    pub(crate) source_incomplete: bool,
    pub(crate) depth_truncated: bool,
}

impl WalkDiagnostics {
    pub(crate) fn incomplete(self) -> bool {
        self.source_incomplete || self.depth_truncated
    }

    pub(crate) fn mark_incomplete(&mut self) {
        self.source_incomplete = true;
    }
}

/// Visit every entry under `config.root` that passes exclusion rules.
#[allow(dead_code)] // Compatibility wrapper for callers without diagnostics.
pub fn walk<F>(config: &WalkConfig, mut on_entry: F)
where
    F: FnMut(&DirEntry),
{
    walk_with_diagnostics(config, |entry| on_entry(entry));
}

/// Visit entries and return traversal and max-depth truncation diagnostics.
pub(crate) fn walk_with_diagnostics<F>(config: &WalkConfig, mut on_entry: F) -> WalkDiagnostics
where
    F: FnMut(&DirEntry),
{
    let mut diagnostics = WalkDiagnostics::default();
    for item in WalkDir::new(&config.root)
        .max_depth(config.max_depth)
        .follow_links(config.follow_links)
        .into_iter()
        .filter_entry(|e| should_enter(e.path(), config))
    {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                diagnostics.source_incomplete = true;
                continue;
            }
        };
        if entry.depth() == config.max_depth && entry.file_type().is_dir() {
            match fs::read_dir(entry.path()) {
                Ok(mut children) => match children.next() {
                    Some(Ok(_)) => diagnostics.depth_truncated = true,
                    Some(Err(_)) => diagnostics.source_incomplete = true,
                    None => {}
                },
                Err(_) => diagnostics.source_incomplete = true,
            }
        }
        on_entry(&entry);
    }
    diagnostics
}

fn should_enter(path: &Path, config: &WalkConfig) -> bool {
    if config.apply_dir_skip_policy || !config.subtree_excludes.is_empty() {
        !policy::is_excluded(path, &config.subtree_excludes)
    } else {
        true
    }
}
