//! Threat-intel surface for agent-collect-trace.
//!
//! Matching / enrich lives in [`agent_detect::ioc`]; this module re-exports it
//! solely as a compatibility surface for existing callers. New composition and
//! feed-adapter code should import detect-layer types directly.

pub mod sync;

pub use agent_detect::ioc::{FeedIndicator, ThreatFeed};
