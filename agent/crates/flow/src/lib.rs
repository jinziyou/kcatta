//! agent-flow library: network metadata capture + IOC matching engine.
//!
//! The library exposes [`run_capture_with_config`] which assembles one batch
//! of observed flow events into a [`FlowBatch`] conforming to the contract
//! published by `analyzer`.
//!
//! Capture backends:
//! - `mock` (default): synthetic flows for CI / dev
//! - `pcap` (feature `pcap`): live libpcap capture with 5-tuple aggregation

pub mod capture;
pub mod cli;
pub mod contract;
pub mod intel;

pub use capture::{CaptureBackend, CaptureConfig};
pub use contract::{FlowBatch, FlowEvent, FlowProto, IndicatorType, Severity, ThreatMatch};
pub use intel::ThreatFeed;

#[cfg(feature = "pcap")]
pub use capture::pcap;

use chrono::Utc;
use uuid::Uuid;

/// Identifier used to attribute the batch (and contained events) to a
/// specific collector deployment. Generated freshly per process for v0;
/// real deployments will pin this via config / environment.
fn fresh_collector_id() -> String {
    format!("collector-{}", Uuid::new_v4())
}

/// Run one capture cycle with mock backend and built-in threat-intel feed.
pub fn run_capture() -> anyhow::Result<FlowBatch> {
    run_capture_with_config(&ThreatFeed::builtin(), &CaptureConfig::default())
}

/// Run one capture cycle: capture -> IOC matching -> `FlowBatch`.
///
/// The returned batch validates against `analyzer/schemas-json/FlowBatch.schema.json`
/// (enforced by `tests/contract.rs` for the mock backend).
pub fn run_capture_with_config(
    feed: &ThreatFeed,
    config: &CaptureConfig,
) -> anyhow::Result<FlowBatch> {
    let collector_id = fresh_collector_id();
    let mut flows = capture::capture(&collector_id, config)?;
    feed.enrich(&mut flows);

    Ok(FlowBatch {
        batch_id: format!("batch-{}", Uuid::new_v4()),
        collected_at: Utc::now(),
        collector_id,
        collector_version: env!("CARGO_PKG_VERSION").to_string(),
        flows,
    })
}
