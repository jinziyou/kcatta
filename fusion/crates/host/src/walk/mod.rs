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
pub use registry::{npm_handler, pypi_handler, walk_project};
