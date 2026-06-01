//! collector-core: cyber-posture network metadata capture engine.
//!
//! The library exposes [`run_capture`] which assembles one batch of
//! observed flow events into a [`FlowBatch`] conforming to the contract
//! published by `form`.
//!
//! v0 ships only the `mock` capture backend; real pcap / AF_PACKET /
//! eBPF backends will plug in behind the same return type.

pub mod capture;
pub mod contract;
pub mod intel;

pub use contract::{FlowBatch, FlowEvent, FlowProto, IndicatorType, Severity, ThreatMatch};
pub use intel::ThreatFeed;

use chrono::Utc;
use uuid::Uuid;

/// Identifier used to attribute the batch (and contained events) to a
/// specific collector deployment. Generated freshly per process for v0;
/// real deployments will pin this via config / environment.
fn fresh_collector_id() -> String {
    format!("collector-{}", Uuid::new_v4())
}

/// Run one capture cycle, enrich with the built-in threat-intel feed, and
/// return a serializable [`FlowBatch`].
///
/// The returned batch is guaranteed to validate against
/// `form/schemas-json/FlowBatch.schema.json` (enforced by the
/// `tests/contract.rs` integration test).
pub fn run_capture() -> anyhow::Result<FlowBatch> {
    run_capture_with_feed(&ThreatFeed::builtin())
}

/// Run one capture cycle and annotate each flow against `feed` before
/// returning the [`FlowBatch`]. This is the full collector pipeline:
/// capture -> preliminary processing (IOC matching).
pub fn run_capture_with_feed(feed: &ThreatFeed) -> anyhow::Result<FlowBatch> {
    let collector_id = fresh_collector_id();
    let mut flows = capture::mock::capture(&collector_id);
    feed.enrich(&mut flows);

    Ok(FlowBatch {
        batch_id: format!("batch-{}", Uuid::new_v4()),
        collected_at: Utc::now(),
        collector_id,
        collector_version: env!("CARGO_PKG_VERSION").to_string(),
        flows,
    })
}
