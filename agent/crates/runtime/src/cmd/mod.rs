//! Subcommand handlers for the `agent` orchestrator. Each module is gated by
//! the cargo feature that pulls in its domain crate.

#[cfg(feature = "flow")]
pub mod flow;
#[cfg(feature = "host")]
pub mod host;
#[cfg(feature = "flow")]
pub mod intel_sync;
