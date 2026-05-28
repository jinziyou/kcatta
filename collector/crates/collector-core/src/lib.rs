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

pub use contract::{FlowBatch, FlowEvent, FlowProto};

use chrono::Utc;
use uuid::Uuid;

/// Identifier used to attribute the batch (and contained events) to a
/// specific collector deployment. Generated freshly per process for v0;
/// real deployments will pin this via config / environment.
fn fresh_collector_id() -> String {
    format!("collector-{}", Uuid::new_v4())
}

/// Run one capture cycle and return a serializable [`FlowBatch`].
///
/// The returned batch is guaranteed to validate against
/// `form/schemas-json/FlowBatch.schema.json` (enforced by the
/// `tests/contract.rs` integration test).
pub fn run_capture() -> anyhow::Result<FlowBatch> {
    let collector_id = fresh_collector_id();
    let flows = capture::mock::capture(&collector_id);

    Ok(FlowBatch {
        batch_id: format!("batch-{}", Uuid::new_v4()),
        collected_at: Utc::now(),
        collector_id,
        collector_version: env!("CARGO_PKG_VERSION").to_string(),
        flows,
    })
}
