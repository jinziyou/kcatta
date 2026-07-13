//! Source-oriented trace collection and result aggregation.
//!
//! A source may emit zero, one, or several typed result groups in a single
//! collection cycle. The aggregator folds those groups into the three streams
//! of one [`TraceBatch`](crate::TraceBatch), preserving source/event order
//! within each typed stream. The wire format has no cross-stream global order.

use agent_contract::{FileTraceEvent, ProcessTraceEvent};
use anyhow::Context as _;
use chrono::Utc;
use uuid::Uuid;

use crate::{TraceBatch, TraceEvent};

/// One typed group emitted by a trace [`Source`].
#[derive(Debug, Clone)]
pub enum SourceResult {
    /// Network flow events.
    NetworkEvents(Vec<TraceEvent>),
    /// File-system operation events.
    FileEvents(Vec<FileTraceEvent>),
    /// Process lifecycle events.
    ProcessEvents(Vec<ProcessTraceEvent>),
}

/// A producer of trace information from one underlying source.
///
/// Sources receive the collector id shared by the whole cycle so every event
/// can be attributed to the same collector. A source may return multiple
/// [`SourceResult`] groups (or none when it observed nothing).
pub trait Source: Send + Sync {
    /// Stable source identifier for diagnostics and plan inspection.
    fn id(&self) -> &'static str;

    /// Collect all currently available result groups from this source.
    fn collect(&self, collector_id: &str) -> anyhow::Result<Vec<SourceResult>>;
}

impl<T> Source for Box<T>
where
    T: Source + ?Sized,
{
    fn id(&self) -> &'static str {
        (**self).id()
    }

    fn collect(&self, collector_id: &str) -> anyhow::Result<Vec<SourceResult>> {
        (**self).collect(collector_id)
    }
}

impl<T> Source for &T
where
    T: Source + ?Sized,
{
    fn id(&self) -> &'static str {
        (**self).id()
    }

    fn collect(&self, collector_id: &str) -> anyhow::Result<Vec<SourceResult>> {
        (**self).collect(collector_id)
    }
}

/// Collect each source in plan order and fold all of its results into one batch.
///
/// Each result is appended to its typed stream in source/result/event order;
/// an empty source leaves the streams unchanged. No ordering is defined across
/// the network, file, and process vectors.
pub fn capture_sources<S>(sources: &[S]) -> anyhow::Result<TraceBatch>
where
    S: Source,
{
    let collector_id = super::fresh_collector_id();
    let mut batch = empty_batch(collector_id);

    for source in sources {
        let results = source
            .collect(&batch.collector_id)
            .with_context(|| format!("collecting trace source {}", source.id()))?;
        for result in results {
            append_result(&mut batch, result);
        }
    }

    // This timestamp describes the completed batch, not the start of a possibly
    // long, sequential pcap + eBPF collection plan.
    batch.collected_at = Utc::now();
    batch.normalize_wire_fields()?;
    batch.validate_nested_wire_bounds()?;
    Ok(batch)
}

fn empty_batch(collector_id: String) -> TraceBatch {
    TraceBatch {
        batch_id: format!("batch-{}", Uuid::new_v4()),
        collected_at: Utc::now(),
        collector_id,
        collector_version: env!("CARGO_PKG_VERSION").to_string(),
        source_agent_id: None,
        source_target_id: None,
        events: Vec::new(),
        file_events: Vec::new(),
        process_events: Vec::new(),
    }
}

fn append_result(batch: &mut TraceBatch, result: SourceResult) {
    match result {
        SourceResult::NetworkEvents(mut events) => batch.events.append(&mut events),
        SourceResult::FileEvents(mut events) => batch.file_events.append(&mut events),
        SourceResult::ProcessEvents(mut events) => batch.process_events.append(&mut events),
    }
}

#[cfg(test)]
mod tests {
    use agent_contract::{FileOp, FileTraceEvent, ProcessEventType, ProcessTraceEvent};
    use chrono::Utc;

    use super::*;

    #[derive(Clone)]
    struct FakeSource {
        results: Vec<SourceResult>,
    }

    impl Source for FakeSource {
        fn id(&self) -> &'static str {
            "fake"
        }

        fn collect(&self, _collector_id: &str) -> anyhow::Result<Vec<SourceResult>> {
            Ok(self.results.clone())
        }
    }

    fn network(trace_id: &str) -> TraceEvent {
        let mut event = crate::capture::mock::capture("fake")
            .into_iter()
            .next()
            .expect("mock event");
        event.trace_id = trace_id.to_string();
        event
    }

    fn file(trace_id: &str) -> FileTraceEvent {
        FileTraceEvent {
            trace_id: trace_id.to_string(),
            host_id: "fake".to_string(),
            ts: Utc::now(),
            pid: 7,
            comm: "fake".to_string(),
            uid: None,
            op: FileOp::Open,
            path: "/tmp/fake".to_string(),
            target_path: None,
            ret: None,
            threat_intel: Vec::new(),
        }
    }

    fn process(trace_id: &str) -> ProcessTraceEvent {
        ProcessTraceEvent {
            trace_id: trace_id.to_string(),
            host_id: "fake".to_string(),
            ts: Utc::now(),
            event_type: ProcessEventType::Exec,
            pid: 7,
            ppid: None,
            uid: None,
            comm: "fake".to_string(),
            exe: None,
            argv: Vec::new(),
            cgroup: None,
            exit_code: None,
            threat_intel: Vec::new(),
        }
    }

    #[test]
    fn one_source_can_emit_multiple_result_types() {
        let sources = [FakeSource {
            results: vec![
                SourceResult::NetworkEvents(vec![network("network-1")]),
                SourceResult::ProcessEvents(vec![process("process-1")]),
                SourceResult::FileEvents(vec![file("file-1")]),
            ],
        }];

        let batch = capture_sources(&sources).expect("capture fake source");
        assert_eq!(batch.events[0].trace_id, "network-1");
        assert_eq!(batch.process_events[0].trace_id, "process-1");
        assert_eq!(batch.file_events[0].trace_id, "file-1");
    }

    #[test]
    fn empty_source_produces_an_empty_batch() {
        let batch = capture_sources(&[FakeSource {
            results: Vec::new(),
        }])
        .expect("capture empty source");

        assert!(batch.events.is_empty());
        assert!(batch.file_events.is_empty());
        assert!(batch.process_events.is_empty());
    }

    #[test]
    fn aggregation_preserves_source_and_event_order() {
        let sources = [
            FakeSource {
                results: vec![SourceResult::NetworkEvents(vec![
                    network("network-1"),
                    network("network-2"),
                ])],
            },
            FakeSource {
                results: vec![
                    SourceResult::FileEvents(vec![file("file-1")]),
                    SourceResult::NetworkEvents(vec![network("network-3")]),
                    SourceResult::FileEvents(vec![file("file-2")]),
                ],
            },
        ];

        let batch = capture_sources(&sources).expect("capture ordered sources");
        let network_ids: Vec<_> = batch
            .events
            .iter()
            .map(|event| event.trace_id.as_str())
            .collect();
        let file_ids: Vec<_> = batch
            .file_events
            .iter()
            .map(|event| event.trace_id.as_str())
            .collect();
        assert_eq!(network_ids, ["network-1", "network-2", "network-3"]);
        assert_eq!(file_ids, ["file-1", "file-2"]);
    }

    #[test]
    fn aggregation_bounds_trace_correlation_ids_but_not_paths() {
        let long = "追踪".repeat(200);
        let mut file_event = file(&long);
        file_event.host_id = long.clone();
        file_event.comm = long.clone();
        file_event.path = format!("/{}", long);
        let expected_path = file_event.path.clone();

        let batch = capture_sources(&[FakeSource {
            results: vec![SourceResult::FileEvents(vec![file_event])],
        }])
        .expect("capture long identifiers");
        let event = &batch.file_events[0];

        assert_eq!(event.trace_id.chars().count(), 256);
        assert_eq!(event.host_id.chars().count(), 256);
        assert_eq!(event.comm.chars().count(), 256);
        assert!(event.trace_id.contains("~sha256:"));
        assert_eq!(event.path, expected_path, "path uses the wider wire bound");
    }
}
