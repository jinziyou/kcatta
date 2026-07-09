//! Threat-intel surface for agent-collect-trace.
//!
//! Matching / enrich lives in [`agent_detect::ioc`]; this module re-exports it
//! for existing `agent_collect_trace::ThreatFeed` callers and hosts feed-sync adapters.

pub mod sync;

pub use agent_detect::ioc::{FeedIndicator, ThreatFeed};
