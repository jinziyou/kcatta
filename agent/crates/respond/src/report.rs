//! Reporting: convert a handled [`Detection`] into a contract
//! [`agent_contract::GuardEvent`], batch events, and flush them to sinks
//! (stdout, a local NDJSON audit log, and/or analyzer).

use agent_contract::{
    ActionTaken, FileIntegrityEvent, GuardEvent, GuardEventBatch, IdsEvent, MalwareEvent,
    NetworkEvent, Outcome, ProcessEvent,
};
use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

use crate::config::ReportConfig;
use crate::context::GuardContext;
use crate::Detection;

/// Form accepts at most this many guard events in one envelope.
const MAX_GUARD_EVENTS_PER_BATCH: usize = 4_096;
/// Keep upload/local contract envelopes below Form's 10 MiB request ceiling.
const MAX_GUARD_BATCH_JSON_BYTES: usize = 9 * 1024 * 1024;

/// Build the reported contract event from a handled detection plus its outcome.
pub fn build_event(
    detection: Detection,
    action_taken: ActionTaken,
    outcome: Outcome,
    ctx: &GuardContext,
) -> GuardEvent {
    let event_id = format!("guard-evt-{}", Uuid::new_v4());
    let timestamp = Utc::now();
    let host_id = ctx.host_id.clone();

    let mut event = match detection {
        Detection::Fim {
            severity,
            path,
            change,
            hash_before,
            hash_after,
        } => GuardEvent::Fim(FileIntegrityEvent {
            event_id,
            timestamp,
            severity,
            host_id,
            action_taken,
            outcome,
            path,
            change_type: change,
            hash_before,
            hash_after,
        }),
        Detection::Malware {
            severity,
            path,
            signature,
            source,
            process_id,
        } => GuardEvent::Malware(MalwareEvent {
            event_id,
            timestamp,
            severity,
            host_id,
            action_taken,
            outcome,
            path,
            signature,
            source,
            process_id,
        }),
        Detection::Process {
            severity,
            pid,
            process_name,
            behavior,
            rule_id,
            evidence,
            parent_pid,
            parent_name,
        } => GuardEvent::Process(ProcessEvent {
            event_id,
            timestamp,
            severity,
            host_id,
            action_taken,
            outcome,
            pid,
            process_name,
            behavior,
            rule_id,
            evidence,
            parent_pid,
            parent_name,
        }),
        Detection::Network {
            severity,
            proto,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            response_ip: _,
            indicator,
            indicator_type,
            category,
            source,
        } => GuardEvent::Network(NetworkEvent {
            event_id,
            timestamp,
            severity,
            host_id,
            action_taken,
            outcome,
            proto,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            indicator,
            indicator_type,
            category,
            source,
        }),
        Detection::Ids {
            severity,
            signature_id,
            signature_name,
            proto,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            response_ip: _,
        } => GuardEvent::Ids(IdsEvent {
            event_id,
            timestamp,
            severity,
            host_id,
            action_taken,
            outcome,
            signature_id,
            signature_name,
            proto,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }),
    };
    event.bound_correlation_ids();
    event.bound_wire_text_fields();
    event
}

/// A destination for flushed event batches.
pub trait ReportSink: Send {
    /// Emit one batch. Errors are logged by the caller and never abort the daemon.
    fn emit(&self, batch: &GuardEventBatch) -> anyhow::Result<()>;

    /// Whether success from this sink constitutes control-plane delivery.
    ///
    /// Local audit/stdout sinks deliberately return `false`: they are useful
    /// evidence copies, but must not make a failed Form upload look delivered.
    /// Transport sinks override this to `true`.  A default keeps third-party
    /// and test sinks source-compatible.
    fn is_delivery_sink(&self) -> bool {
        false
    }
}

/// Print each batch as one JSON line to stdout (dev).
pub struct StdoutSink;

impl ReportSink for StdoutSink {
    fn emit(&self, batch: &GuardEventBatch) -> anyhow::Result<()> {
        println!("{}", serde_json::to_string(batch)?);
        Ok(())
    }
}

/// Append each batch as one JSON line to a local NDJSON audit log.
pub struct NdjsonSink {
    path: std::path::PathBuf,
    max_bytes: u64,
    limit_warned: AtomicBool,
}

impl NdjsonSink {
    /// Create a sink writing to `path`, capped at 64 MiB.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self::with_max_bytes(path, 64 * 1024 * 1024)
    }

    /// Create a sink with an explicit hard byte cap.
    pub fn with_max_bytes(path: impl Into<std::path::PathBuf>, max_bytes: u64) -> Self {
        Self {
            path: path.into(),
            max_bytes,
            limit_warned: AtomicBool::new(false),
        }
    }

    /// Validate and prepare a configured audit path before registering the sink.
    pub fn try_with_max_bytes(
        path: impl Into<std::path::PathBuf>,
        max_bytes: u64,
    ) -> anyhow::Result<Self> {
        let sink = Self::with_max_bytes(path, max_bytes);
        crate::audit::prepare(&sink.path)?;
        Ok(sink)
    }
}

impl ReportSink for NdjsonSink {
    fn emit(&self, batch: &GuardEventBatch) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(batch)?;
        line.push(b'\n');
        match crate::audit::append(&self.path, &line, self.max_bytes)? {
            crate::audit::AppendOutcome::Written => {}
            crate::audit::AppendOutcome::Reset => {
                if !self.limit_warned.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "guard: local NDJSON audit reached its {} byte limit; reset in place and retained the newest complete batch",
                        self.max_bytes
                    );
                }
            }
            crate::audit::AppendOutcome::RecordTooLarge => {
                if !self.limit_warned.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "guard: local NDJSON audit batch exceeds its {} byte limit; dropping oversized local copy (other report sinks are unaffected)",
                        self.max_bytes
                    );
                }
            }
        }
        Ok(())
    }
}

/// Accumulates events and flushes them as [`GuardEventBatch`]es to all sinks.
pub struct Reporter {
    ctx: GuardContext,
    sinks: Vec<Box<dyn ReportSink>>,
    buffer: Vec<GuardEvent>,
    batch_max: usize,
    /// Cap on events retained in the buffer during a total-outage re-buffer
    /// (see [`Reporter::flush`]). Bounds memory under a sustained outage.
    max_buffer: usize,
}

impl Reporter {
    /// Build a reporter with explicit sinks (used by tests).
    pub fn with_sinks(
        ctx: GuardContext,
        sinks: Vec<Box<dyn ReportSink>>,
        batch_max: usize,
    ) -> Self {
        let batch_max = batch_max.clamp(1, MAX_GUARD_EVENTS_PER_BATCH);
        Self {
            ctx,
            sinks,
            buffer: Vec::new(),
            batch_max,
            max_buffer: batch_max.saturating_mul(200).max(1000),
        }
    }

    /// Build a reporter from config: stdout (opt) + local NDJSON audit (opt),
    /// plus any caller-injected `extra_sinks` (e.g. the `agentd respond --upload`
    /// Form sink). With no sinks at all, falls back to stdout so the daemon is
    /// never silently dropping events. The guard library itself never uploads —
    /// transport sinks are injected from outside (see the umbrella `agentd`).
    pub fn from_config(
        ctx: GuardContext,
        cfg: &ReportConfig,
        extra_sinks: Vec<Box<dyn ReportSink>>,
    ) -> Self {
        let mut sinks: Vec<Box<dyn ReportSink>> = Vec::new();
        if cfg.stdout {
            sinks.push(Box::new(StdoutSink));
        }
        if let Some(path) = &cfg.audit_log {
            match NdjsonSink::try_with_max_bytes(path.clone(), cfg.audit_max_bytes) {
                Ok(sink) => sinks.push(Box::new(sink)),
                Err(error) => eprintln!(
                    "guard: local NDJSON audit disabled for {}: {error}",
                    path.display()
                ),
            }
        }
        sinks.extend(extra_sinks);
        if sinks.is_empty() {
            sinks.push(Box::new(StdoutSink));
        }
        Self::with_sinks(ctx, sinks, cfg.batch_max)
    }

    /// Buffer a built event, flushing automatically at `batch_max`.
    pub fn record(&mut self, detection: Detection, action_taken: ActionTaken, outcome: Outcome) {
        let event = build_event(detection, action_taken, outcome, &self.ctx);
        self.buffer.push(event);
        if self.buffer.len() >= self.batch_max {
            self.flush();
        }
    }

    /// Number of events buffered but not yet flushed.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// Flush the buffer as one batch to every sink (errors logged, never fatal).
    ///
    /// Events are taken out to build the batch, but are re-buffered when no
    /// configured delivery sink accepts them. Local audit/stdout success does
    /// not mask a failed Form transport. When there is no delivery sink, the
    /// historical behaviour is retained and any successful local sink counts.
    /// The re-buffer is bounded by [`Self::max_buffer`] (oldest events dropped,
    /// with a count) so a sustained outage cannot grow memory without limit.
    pub fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let mut batch = GuardEventBatch {
            batch_id: format!("guard-batch-{}", Uuid::new_v4()),
            collected_at: Utc::now(),
            host_id: self.ctx.host_id.clone(),
            agent_version: self.ctx.agent_version.clone(),
            source_agent_id: None,
            source_target_id: None,
            events: std::mem::take(&mut self.buffer),
        };
        batch.bound_correlation_ids();
        batch.bound_wire_text_fields();
        let batches = match split_guard_batch(&batch) {
            Ok(batches) => batches,
            Err(error) => {
                eprintln!("guard: cannot form a schema-safe report batch: {error}");
                // The only unsplittable case is one oversized event. Retaining
                // the original events makes the failure loud and lossless; the
                // bounded buffer still protects the daemon from unbounded RAM.
                self.buffer = batch.events;
                return;
            }
        };

        let mut retry_events = Vec::new();
        let has_delivery_sink = self.sinks.iter().any(|sink| sink.is_delivery_sink());
        for batch in batches {
            // With no sinks at all there is nothing to retain for. If a
            // control-plane delivery sink exists, only its acceptance clears
            // the batch; local evidence copies remain auxiliary.
            let mut delivered = self.sinks.is_empty();
            for sink in &self.sinks {
                match sink.emit(&batch) {
                    Ok(()) if !has_delivery_sink || sink.is_delivery_sink() => delivered = true,
                    Ok(()) => {}
                    Err(e) => eprintln!("guard: report sink failed: {e}"),
                }
            }
            if !delivered {
                retry_events.extend(batch.events);
            }
        }
        if !retry_events.is_empty() {
            let overflow = retry_events.len().saturating_sub(self.max_buffer);
            if overflow > 0 {
                retry_events.drain(0..overflow);
                eprintln!(
                    "guard: all report sinks down; buffer full, dropped {overflow} oldest event(s)"
                );
            }
            self.buffer = retry_events;
        }
    }
}

/// Split one batch without losing or truncating events. The byte accounting is
/// exact for JSON arrays: serialize the empty envelope once, then add each
/// serialized item plus its comma. A worst-case JSON-escaped 256-character
/// batch id is used while packing so assigning child ids can never push a
/// result over budget, even when the original id contains control characters.
fn split_guard_batch(batch: &GuardEventBatch) -> anyhow::Result<Vec<GuardEventBatch>> {
    let mut normalized = batch.clone();
    normalized.normalize_wire_fields()?;
    let batch = &normalized;
    let original_id = batch.batch_id.clone();
    if batch.events.is_empty() {
        return Ok(vec![batch.clone()]);
    }

    let mut sizing_template = batch.clone();
    sizing_template.events.clear();
    sizing_template.batch_id = "\0".repeat(agent_contract::CORRELATION_IDENTIFIER_MAX_CHARS);
    let empty_bytes = serde_json::to_vec(&sizing_template)?.len();
    anyhow::ensure!(
        empty_bytes <= MAX_GUARD_BATCH_JSON_BYTES,
        "empty guard envelope is {empty_bytes} bytes (limit {MAX_GUARD_BATCH_JSON_BYTES})"
    );

    let mut chunks = Vec::new();
    let mut current = sizing_template.clone();
    current.batch_id = original_id.clone();
    let mut current_bytes = empty_bytes;
    for event in batch.events.iter().cloned() {
        let event_bytes = serde_json::to_vec(&event)?.len();
        let separator = usize::from(!current.events.is_empty());
        let exceeds_count = current.events.len() >= MAX_GUARD_EVENTS_PER_BATCH;
        let exceeds_bytes = current_bytes
            .saturating_add(separator)
            .saturating_add(event_bytes)
            > MAX_GUARD_BATCH_JSON_BYTES;
        if exceeds_count || exceeds_bytes {
            anyhow::ensure!(
                !current.events.is_empty(),
                "one guard event needs {} bytes in its envelope (limit {})",
                empty_bytes.saturating_add(event_bytes),
                MAX_GUARD_BATCH_JSON_BYTES
            );
            chunks.push(current);
            current = sizing_template.clone();
            current.batch_id = original_id.clone();
            current_bytes = empty_bytes;
        }
        let separator = usize::from(!current.events.is_empty());
        anyhow::ensure!(
            current_bytes
                .saturating_add(separator)
                .saturating_add(event_bytes)
                <= MAX_GUARD_BATCH_JSON_BYTES,
            "one guard event needs {} bytes in its envelope (limit {})",
            empty_bytes.saturating_add(event_bytes),
            MAX_GUARD_BATCH_JSON_BYTES
        );
        current.events.push(event);
        current_bytes += separator + event_bytes;
    }
    if !current.events.is_empty() {
        chunks.push(current);
    }

    let total = chunks.len();
    for (index, chunk) in chunks.iter_mut().enumerate() {
        if total > 1 {
            chunk.batch_id = agent_contract::bounded_correlation_id(&format!(
                "{original_id}::chunk-{}-of-{total}",
                index + 1
            ));
        }
        chunk.bound_correlation_ids();
        chunk.normalize_wire_fields()?;
        chunk.validate_envelope_list_bounds()?;
        let encoded_len = serde_json::to_vec(&*chunk)?.len();
        anyhow::ensure!(
            chunk.events.len() <= MAX_GUARD_EVENTS_PER_BATCH
                && encoded_len <= MAX_GUARD_BATCH_JSON_BYTES,
            "internal guard chunking invariant failed"
        );
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_contract::{FimChange, Severity};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct MemSink(Arc<Mutex<Vec<GuardEventBatch>>>);

    impl ReportSink for MemSink {
        fn emit(&self, batch: &GuardEventBatch) -> anyhow::Result<()> {
            self.0.lock().unwrap().push(batch.clone());
            Ok(())
        }
    }

    fn ctx() -> GuardContext {
        GuardContext {
            host_id: "h-1".into(),
            agent_version: "0.1.0".into(),
        }
    }

    fn fim() -> Detection {
        Detection::Fim {
            severity: Severity::Medium,
            path: "/etc/hosts".into(),
            change: FimChange::Modified,
            hash_before: None,
            hash_after: Some("abc".into()),
        }
    }

    #[test]
    fn flushes_at_batch_max() {
        let sink = MemSink::default();
        let mut reporter = Reporter::with_sinks(ctx(), vec![Box::new(sink.clone())], 2);

        reporter.record(fim(), ActionTaken::Logged, Outcome::Success);
        assert_eq!(reporter.pending(), 1);
        assert!(sink.0.lock().unwrap().is_empty());

        reporter.record(fim(), ActionTaken::Logged, Outcome::Success);
        assert_eq!(reporter.pending(), 0, "auto-flushed at batch_max");

        let batches = sink.0.lock().unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].events.len(), 2);
        assert_eq!(batches[0].host_id, "h-1");
    }

    #[test]
    fn manual_flush_emits_remainder() {
        let sink = MemSink::default();
        let mut reporter = Reporter::with_sinks(ctx(), vec![Box::new(sink.clone())], 50);
        reporter.record(fim(), ActionTaken::Logged, Outcome::Success);
        reporter.flush();
        assert_eq!(sink.0.lock().unwrap()[0].events.len(), 1);
    }

    #[test]
    fn splits_guard_batches_without_losing_events_or_exceeding_schema_caps() {
        let event = build_event(fim(), ActionTaken::Logged, Outcome::Success, &ctx());
        let batch = GuardEventBatch {
            batch_id: "guard-source".into(),
            collected_at: Utc::now(),
            host_id: "host-1".into(),
            agent_version: "test".into(),
            source_agent_id: Some("agent-1".into()),
            source_target_id: Some("target-1".into()),
            events: vec![event; MAX_GUARD_EVENTS_PER_BATCH + 1],
        };

        let chunks = split_guard_batch(&batch).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks.iter().map(|chunk| chunk.events.len()).sum::<usize>(),
            batch.events.len()
        );
        assert!(chunks
            .iter()
            .all(|chunk| chunk.events.len() <= MAX_GUARD_EVENTS_PER_BATCH));
        assert_ne!(chunks[0].batch_id, chunks[1].batch_id);
        assert!(chunks.iter().all(|chunk| {
            chunk.source_agent_id.as_deref() == Some("agent-1")
                && chunk.source_target_id.as_deref() == Some("target-1")
        }));
        assert!(chunks.iter().all(|chunk| {
            chunk.batch_id.chars().count() <= agent_contract::CORRELATION_IDENTIFIER_MAX_CHARS
                && serde_json::to_vec(chunk).unwrap().len() <= MAX_GUARD_BATCH_JSON_BYTES
        }));
    }

    #[test]
    fn splits_guard_batches_at_the_json_body_budget() {
        let event = build_event(
            Detection::Process {
                severity: Severity::High,
                pid: 42,
                process_name: "worker".into(),
                behavior: "test".into(),
                rule_id: "rule".into(),
                evidence: Some("e".repeat(4_000)),
                parent_pid: None,
                parent_name: None,
            },
            ActionTaken::Logged,
            Outcome::Success,
            &ctx(),
        );
        let batch = GuardEventBatch {
            batch_id: "guard-large".into(),
            collected_at: Utc::now(),
            host_id: "host-1".into(),
            agent_version: "test".into(),
            source_agent_id: None,
            source_target_id: None,
            events: vec![event; 2_500],
        };
        assert!(serde_json::to_vec(&batch).unwrap().len() > MAX_GUARD_BATCH_JSON_BYTES);

        let chunks = split_guard_batch(&batch).unwrap();
        assert!(chunks.len() > 1);
        assert_eq!(
            chunks.iter().map(|chunk| chunk.events.len()).sum::<usize>(),
            2_500
        );
        assert!(chunks
            .iter()
            .all(|chunk| serde_json::to_vec(chunk).unwrap().len() <= MAX_GUARD_BATCH_JSON_BYTES));
    }

    #[test]
    fn guard_context_and_event_correlation_fields_are_bounded() {
        use agent_contract::{IndicatorType, TraceProto};

        let long = "界".repeat(300);
        let ctx = GuardContext::new(Some(long.clone()), long.clone());
        assert!(ctx.host_id.chars().count() <= 256);
        assert!(ctx.agent_version.chars().count() <= 256);

        let detections = [
            Detection::Malware {
                severity: Severity::Critical,
                path: long.clone(),
                signature: long.clone(),
                source: long.clone(),
                process_id: None,
            },
            Detection::Network {
                severity: Severity::High,
                proto: TraceProto::Tcp,
                src_ip: "192.0.2.1".into(),
                src_port: Some(1),
                dst_ip: "198.51.100.1".into(),
                dst_port: Some(2),
                response_ip: None,
                indicator: long.clone(),
                indicator_type: IndicatorType::Domain,
                category: long.clone(),
                source: long.clone(),
            },
            Detection::Ids {
                severity: Severity::High,
                signature_id: long.clone(),
                signature_name: long.clone(),
                proto: TraceProto::Tcp,
                src_ip: "192.0.2.1".into(),
                src_port: Some(1),
                dst_ip: "198.51.100.1".into(),
                dst_port: Some(2),
                response_ip: None,
            },
            Detection::Process {
                severity: Severity::High,
                pid: 42,
                process_name: long.clone(),
                behavior: long.clone(),
                rule_id: long.clone(),
                evidence: Some("e".repeat(5_000)),
                parent_pid: None,
                parent_name: None,
            },
        ];

        for detection in detections {
            let event = build_event(detection, ActionTaken::Logged, Outcome::Success, &ctx);
            match event {
                GuardEvent::Malware(event) => {
                    assert_eq!(event.path, long, "path must use its wider wire bound");
                    assert!(event.signature.chars().count() <= 256);
                    assert!(event.source.chars().count() <= 256);
                }
                GuardEvent::Network(event) => {
                    assert!(event.indicator.chars().count() <= 256);
                    assert!(event.category.chars().count() <= 256);
                    assert!(event.source.chars().count() <= 256);
                }
                GuardEvent::Ids(event) => {
                    assert!(event.signature_id.chars().count() <= 256);
                    assert!(event.signature_name.chars().count() <= 256);
                }
                GuardEvent::Process(event) => {
                    assert!(event.process_name.chars().count() <= 256);
                    assert!(event.behavior.chars().count() <= 256);
                    assert!(event.rule_id.chars().count() <= 256);
                    let evidence = event.evidence.as_deref().unwrap();
                    assert_eq!(evidence.chars().count(), 4_096);
                    assert!(evidence.contains("~sha256:"));
                }
                GuardEvent::Fim(_) => unreachable!(),
            }
        }
    }

    /// A sink that always fails, to exercise the total-outage re-buffer path.
    struct FailSink;
    impl ReportSink for FailSink {
        fn emit(&self, _batch: &GuardEventBatch) -> anyhow::Result<()> {
            anyhow::bail!("sink down")
        }
    }

    struct DeliveryFailSink;
    impl ReportSink for DeliveryFailSink {
        fn emit(&self, _batch: &GuardEventBatch) -> anyhow::Result<()> {
            anyhow::bail!("Form down")
        }

        fn is_delivery_sink(&self) -> bool {
            true
        }
    }

    #[test]
    fn rebuffers_events_when_all_sinks_fail() {
        let mut reporter = Reporter::with_sinks(ctx(), vec![Box::new(FailSink)], 50);
        reporter.record(fim(), ActionTaken::Logged, Outcome::Success);
        reporter.flush();
        // Total outage: the event must survive in the buffer for the next flush
        // rather than being dropped.
        assert_eq!(
            reporter.pending(),
            1,
            "events re-buffered on total sink outage"
        );
    }

    #[test]
    fn one_working_sink_means_delivered_not_rebuffered() {
        let good = MemSink::default();
        let mut reporter =
            Reporter::with_sinks(ctx(), vec![Box::new(FailSink), Box::new(good.clone())], 50);
        reporter.record(fim(), ActionTaken::Logged, Outcome::Success);
        reporter.flush();
        // The audit (good) sink accepted it → not re-buffered even though the
        // analyzer (fail) sink errored.
        assert_eq!(reporter.pending(), 0);
        assert_eq!(good.0.lock().unwrap()[0].events.len(), 1);
    }

    #[test]
    fn local_audit_success_does_not_mask_form_delivery_failure() {
        let audit = MemSink::default();
        let mut reporter = Reporter::with_sinks(
            ctx(),
            vec![Box::new(audit.clone()), Box::new(DeliveryFailSink)],
            50,
        );
        reporter.record(fim(), ActionTaken::Logged, Outcome::Success);
        reporter.flush();

        assert_eq!(audit.0.lock().unwrap()[0].events.len(), 1);
        assert_eq!(
            reporter.pending(),
            1,
            "Form delivery failure must remain pending despite a local audit copy"
        );
    }

    #[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
    #[test]
    fn from_config_prepares_a_secure_audit_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/audit.ndjson");
        let config = ReportConfig {
            audit_log: Some(path.clone()),
            batch_max: 1,
            ..ReportConfig::default()
        };

        let mut reporter = Reporter::from_config(ctx(), &config, Vec::new());
        reporter.record(fim(), ActionTaken::Logged, Outcome::Success);

        assert_eq!(reporter.pending(), 0);
        assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 1);
    }

    #[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
    #[test]
    fn unsafe_configured_audit_is_omitted_without_breaking_reporting() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let path = dir.path().join("audit.ndjson");
        symlink(&victim, &path).unwrap();
        let config = ReportConfig {
            audit_log: Some(path),
            batch_max: 1,
            ..ReportConfig::default()
        };

        // The unsafe sink is rejected at construction; with no Form/stdout
        // sink configured, Reporter falls back to stdout instead of making the
        // guard daemon fail or silently lose the event.
        let mut reporter = Reporter::from_config(ctx(), &config, Vec::new());
        reporter.record(fim(), ActionTaken::Logged, Outcome::Success);

        assert_eq!(reporter.pending(), 0);
        assert_eq!(std::fs::read(victim).unwrap(), b"keep");
    }
}
