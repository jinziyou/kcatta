//! agent-collect-trace library: network/file/process **collect** + IOC detect orchestration.
//!
//! Pipeline (same idea as host `run_scan_with_detect`):
//! - [`capture_batch`] — collect-only: raw events into a [`TraceBatch`]
//! - [`enrich_batch`] — detect: [`ThreatFeed`] IOC annotation of `events`
//! - [`run_capture_with_detect`] — convenience: capture then enrich
//!
//! Capture backends:
//! - `mock` (default): synthetic events for CI / dev
//! - `pcap` (feature `pcap`): live libpcap capture with 5-tuple aggregation
//!
//! Beyond the network stream, the `ebpf` feature adds a kernel tracer
//! ([`ebpf`]) that fills the batch's file-operation and process-call streams
//! from eBPF tracepoints.

pub mod capture;
pub mod cli;
pub mod contract;
pub mod intel;

#[cfg(feature = "ebpf")]
pub mod ebpf;

pub use capture::{CaptureBackend, CaptureConfig};
pub use contract::{IndicatorType, Severity, ThreatMatch, TraceBatch, TraceEvent, TraceProto};
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

/// Collect-only: one capture cycle with **no** IOC enrichment.
///
/// Callers that need threat-intel annotation should run [`enrich_batch`]
/// (or [`run_capture_with_detect`]).
pub fn capture_batch(config: &CaptureConfig) -> anyhow::Result<TraceBatch> {
    let collector_id = fresh_collector_id();
    let events = capture::capture(&collector_id, config)?;

    Ok(TraceBatch {
        batch_id: format!("batch-{}", Uuid::new_v4()),
        collected_at: Utc::now(),
        collector_id,
        collector_version: env!("CARGO_PKG_VERSION").to_string(),
        events,
        // File / process streams are populated by the eBPF tracer;
        // the network-capture path leaves them empty.
        file_events: Vec::new(),
        process_events: Vec::new(),
    })
}

/// Detect phase: annotate `batch.events` in place with IOC matches.
///
/// Engine lives in [`agent_detect::ioc`] (re-exported as [`ThreatFeed`]).
pub fn enrich_batch(feed: &ThreatFeed, batch: &mut TraceBatch) {
    feed.enrich(&mut batch.events);
}

/// Run one capture cycle with mock backend and built-in threat-intel feed.
pub fn run_capture() -> anyhow::Result<TraceBatch> {
    run_capture_with_detect(&ThreatFeed::builtin(), &CaptureConfig::default())
}

/// Collect then detect: [`capture_batch`] → [`enrich_batch`].
///
/// Prefer calling the two steps separately at orchestration sites (CLI /
/// agentd / guard) so collect vs detect stays visible. This wrapper remains
/// for short call sites and tests.
///
/// The returned batch validates against `analyzer/schemas-json/TraceBatch.schema.json`
/// (enforced by `tests/contract.rs` for the mock backend).
pub fn run_capture_with_detect(
    feed: &ThreatFeed,
    config: &CaptureConfig,
) -> anyhow::Result<TraceBatch> {
    let mut batch = capture_batch(config)?;
    enrich_batch(feed, &mut batch);
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_batch_leaves_events_unenriched() {
        let batch = capture_batch(&CaptureConfig::default()).expect("capture");
        // Mock backend always emits at least one event; none should carry IOC
        // hits until enrich runs.
        assert!(
            !batch.events.is_empty(),
            "mock capture should produce events"
        );
        assert!(
            batch
                .events
                .iter()
                .all(|e| e.threat_intel.is_empty()),
            "collect-only path must not attach threat_intel"
        );
    }

    #[test]
    fn enrich_batch_annotates_after_capture() {
        let mut batch = capture_batch(&CaptureConfig::default()).expect("capture");
        enrich_batch(&ThreatFeed::builtin(), &mut batch);
        assert!(
            batch.events.iter().any(|e| !e.threat_intel.is_empty()),
            "detect phase should annotate at least one mock event"
        );
    }

    #[test]
    fn run_capture_with_detect_enriches() {
        let feed = ThreatFeed::builtin();
        let batch = run_capture_with_detect(&feed, &CaptureConfig::default()).expect("capture");
        // Builtin feed matches the mock C2 IP used by the mock backend.
        assert!(
            batch.events.iter().any(|e| !e.threat_intel.is_empty()),
            "enrichment wrapper should annotate at least one mock event"
        );
    }
}
