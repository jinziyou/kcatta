//! Trace sources grouped by the origin of their information.

/// Network flow source backed by the existing capture configuration.
pub mod network;

/// Kernel process and file-event source.
#[cfg(feature = "ebpf")]
pub mod ebpf;

pub use network::NetworkSource;

#[cfg(feature = "ebpf")]
pub use ebpf::EbpfSource;
