//! Pattern registry: map walk entries to package extractors.
//!
//! Handlers are registered by match predicate + extract function. Collectors
//! invoke [`walk_project`] (single handler) or [`walk_project_all`] (combined).

use std::path::Path;

use walkdir::DirEntry;

use super::engine::{walk, WalkConfig};
use super::handlers;

/// Bound the recursive project-root walk so a huge tree can't stall a scan.
pub const PYPI_PROJECT_DEPTH: usize = 12;

/// npm project trees may nest deeper (transitive `node_modules`).
pub const NPM_PROJECT_DEPTH: usize = 16;

/// One pattern-matched extractor invoked during a bounded project-root walk.
pub struct ProjectHandler {
    pub max_depth: usize,
    pub matches: fn(&DirEntry) -> bool,
    pub extract: fn(&DirEntry) -> Option<(String, String)>,
}

const PYPI_HANDLER: ProjectHandler = ProjectHandler {
    max_depth: PYPI_PROJECT_DEPTH,
    matches: handlers::pypi::matches,
    extract: handlers::pypi::extract,
};

const NPM_HANDLER: ProjectHandler = ProjectHandler {
    max_depth: NPM_PROJECT_DEPTH,
    matches: handlers::npm::matches,
    extract: handlers::npm::extract,
};

/// PyPI handler: `*.dist-info/METADATA` and `*.egg-info/PKG-INFO`.
pub fn pypi_handler() -> ProjectHandler {
    PYPI_HANDLER
}

/// npm handler: `node_modules/**/package.json`.
pub fn npm_handler() -> ProjectHandler {
    NPM_HANDLER
}

/// Walk `root` and collect packages matching a single handler.
pub fn walk_project(root: &Path, handler: &ProjectHandler) -> Vec<(String, String)> {
    walk_project_all(root, std::slice::from_ref(handler))
}

/// Walk `root` once, dispatching every registered handler per entry.
pub fn walk_project_all(root: &Path, handlers: &[ProjectHandler]) -> Vec<(String, String)> {
    if handlers.is_empty() {
        return Vec::new();
    }
    let max_depth = handlers
        .iter()
        .map(|h| h.max_depth)
        .max()
        .expect("non-empty handlers");
    let config = WalkConfig::at(root, max_depth);
    let mut out = Vec::new();
    walk(&config, |entry| {
        for handler in handlers {
            if !(handler.matches)(entry) {
                continue;
            }
            if let Some(pkg) = (handler.extract)(entry) {
                out.push(pkg);
            }
        }
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_pypi_dist_info(base: &Path, name: &str, version: &str) {
        let folder = format!("{name}-{version}.dist-info");
        let dir = base.join(folder);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("METADATA"), format!("Name: {name}\nVersion: {version}\n")).unwrap();
    }

    fn write_npm_pkg(base: &Path, name: &str, version: &str) {
        fs::create_dir_all(base).unwrap();
        fs::write(
            base.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
    }

    #[test]
    fn walk_project_all_finds_pypi_and_npm_in_one_pass() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("srv/app");
        write_pypi_dist_info(
            &root.join(".venv/lib/python3.11/site-packages"),
            "Flask",
            "3.0.0",
        );
        write_npm_pkg(&root.join("node_modules/express"), "express", "4.18.2");
        write_npm_pkg(
            &root.join("node_modules/express/node_modules/qs"),
            "qs",
            "6.11.0",
        );
        write_npm_pkg(&root, "my-app", "0.1.0");

        let pkgs = walk_project_all(&root, &[pypi_handler(), npm_handler()]);
        let mut names: Vec<String> = pkgs.into_iter().map(|(n, _)| n).collect();
        names.sort();
        assert_eq!(names, vec!["express", "flask", "qs"]);
    }

    #[test]
    fn walk_project_single_handler_isolates_ecosystem() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("proj");
        write_pypi_dist_info(
            &root.join(".venv/lib/python3.11/site-packages"),
            "Django",
            "5.0.0",
        );
        write_npm_pkg(&root.join("node_modules/lodash"), "lodash", "4.0.0");

        let pypi = walk_project(&root, &pypi_handler());
        assert_eq!(pypi.len(), 1);
        assert_eq!(pypi[0].0, "django");

        let npm = walk_project(&root, &npm_handler());
        assert_eq!(npm.len(), 1);
        assert_eq!(npm[0].0, "lodash");
    }
}
