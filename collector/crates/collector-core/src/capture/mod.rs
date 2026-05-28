//! Flow capture backends.
//!
//! v0 ships only a `mock` backend that synthesizes representative flow
//! events without touching the network stack -- enough to exercise the
//! end-to-end pipeline and validate cross-language contract conformance.
//!
//! Future backends (pcap / AF_PACKET / eBPF) plug in alongside `mock`
//! behind the same return type, so callers in `lib.rs` need not change.

pub mod mock;
