//! Inventory sources grouped by where their information comes from.

pub(crate) mod accounts;
pub(crate) mod configuration;
pub(crate) mod credentials;
pub(crate) mod data_services;
pub mod filesystem;
pub(crate) mod host;
pub(crate) mod mounts;
pub(crate) mod network_services;
pub(crate) mod packages;
pub(crate) mod ports;
pub(crate) mod processes;
pub(crate) mod security_controls;
pub(crate) mod services;
// posture / secrets engines moved to `agent-detect` (P2); collectors call them directly.

pub use filesystem::FilesystemSource;
