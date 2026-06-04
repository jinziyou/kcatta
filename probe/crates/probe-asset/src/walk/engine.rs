//! Unified bounded WalkDir wrapper for static asset discovery.

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

/// Visit every entry under `config.root` that passes exclusion rules.
pub fn walk<F>(config: &WalkConfig, mut on_entry: F)
where
    F: FnMut(&DirEntry),
{
    for entry in WalkDir::new(&config.root)
        .max_depth(config.max_depth)
        .follow_links(config.follow_links)
        .into_iter()
        .filter_entry(|e| should_enter(e.path(), config))
        .filter_map(Result::ok)
    {
        on_entry(&entry);
    }
}

fn should_enter(path: &Path, config: &WalkConfig) -> bool {
    if config.apply_dir_skip_policy || !config.subtree_excludes.is_empty() {
        !policy::is_excluded(path, &config.subtree_excludes)
    } else {
        true
    }
}
