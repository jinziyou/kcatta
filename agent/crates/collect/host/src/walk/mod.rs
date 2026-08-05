//! Bounded filesystem walks for static asset discovery.
//!
//! - [`engine`] — shared WalkDir wrapper with depth and skip policy
//! - [`policy`] — pseudo-fs and directory prune rules
//! - [`markers`] — project-root auto-discovery from marker files
//! - [`registry`] — pattern-matched project walks (PyPI, npm, …)
//! - [`handlers`] — individual match/extract implementations

mod engine;
pub(crate) mod handlers;
mod markers;
mod policy;
mod registry;

pub use markers::discover_project_roots;
pub(crate) use markers::discover_project_roots_with_diagnostics;
#[allow(unused_imports)] // Compatibility export for crate-local callers.
pub use registry::walk_project;
pub(crate) use registry::walk_project_with_diagnostics;
pub use registry::{npm_handler, pypi_handler};
