//! Fixed-path asset sources for static filesystem scans.

pub mod accounts;
pub mod credentials;
pub mod host;
pub mod packages;
pub mod ports;
pub mod services;
// posture / secrets engines moved to `agent-detect` (P2); collectors call them directly.
