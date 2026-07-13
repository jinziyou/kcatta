//! Inventory sources grouped by where their information comes from.

pub(crate) mod accounts;
pub(crate) mod credentials;
pub mod filesystem;
pub(crate) mod host;
pub(crate) mod packages;
pub(crate) mod ports;
pub(crate) mod services;
// posture / secrets engines moved to `agent-detect` (P2); collectors call them directly.

pub use filesystem::FilesystemSource;
