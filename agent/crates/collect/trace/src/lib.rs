//! agent-collect-trace library: network/file/process collection.
//!
//! The core API ([`Source`], [`capture_sources`], and [`capture_batch`]) only
//! collects raw events into a [`TraceBatch`]. IOC matching belongs to
//! [`agent_detect::ioc`]. The root [`ThreatFeed`] re-export, [`enrich_batch`],
//! and [`run_capture_with_detect`] remain as compatibility composition facades
//! for existing callers.
//!
//! Capture backends:
//! - `mock` (default): synthetic events for CI / dev
//! - `pcap` (feature `pcap`): live libpcap capture with 5-tuple aggregation
//! - `winnet` (feature `winnet`): live OS connection-table polling
//! - `ebpf` (feature `ebpf`): live cgroup-skb network telemetry; without pcap,
//!   backend failure is returned rather than falling back to mock
//!
//! Beyond the network stream, the `ebpf` feature adds a kernel tracer
//! ([`ebpf`]) that fills the batch's file-operation and process-call streams
//! from eBPF tracepoints.

pub mod capture;
pub mod cli;
pub mod contract;
pub mod intel;
pub mod source;
pub mod sources;

#[cfg(feature = "ebpf")]
pub mod ebpf;

/// Compatibility re-export; new composition code should import this type from
/// [`agent_detect::ioc`] directly.
pub use agent_detect::ioc::ThreatFeed;
pub use capture::{CaptureBackend, CaptureConfig};
pub use contract::{
    FileTraceEvent, IndicatorType, ProcessTraceEvent, Severity, ThreatMatch, TraceBatch,
    TraceEvent, TraceProto,
};
pub use source::{capture_sources, Source, SourceResult};

#[cfg(feature = "pcap")]
pub use capture::pcap;

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
    let source = sources::NetworkSource::new(config.clone());
    capture_sources(std::slice::from_ref(&source))
}

/// Compatibility detect facade: annotate `batch.events` with IOC matches.
///
/// New composition code should call [`ThreatFeed::enrich`] directly so the
/// collection/detection stage boundary stays explicit.
pub fn enrich_batch(feed: &ThreatFeed, batch: &mut TraceBatch) {
    feed.enrich(&mut batch.events);
}

/// Compatibility composition facade: mock capture followed by built-in IOC detection.
pub fn run_capture() -> anyhow::Result<TraceBatch> {
    run_capture_with_detect(&ThreatFeed::builtin(), &CaptureConfig::default())
}

/// Compatibility composition facade: [`capture_batch`] followed by IOC detection.
///
/// New orchestration code should capture first and then call
/// [`ThreatFeed::enrich`] directly so collect vs detect stays visible.
///
/// The returned batch validates against `form/schemas-json/TraceBatch.schema.json`
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
            batch.events.iter().all(|e| e.threat_intel.is_empty()),
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
