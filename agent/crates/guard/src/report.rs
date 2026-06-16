//! Reporting: turn a handled [`Detection`] into a contract
//! [`agent_contract::GuardEvent`], batch events, and flush them to sinks
//! (stdout, a local NDJSON audit log, and/or analyzer).

use agent_contract::{
    ActionTaken, FileIntegrityEvent, GuardEvent, GuardEventBatch, IdsEvent, MalwareEvent,
    NetworkEvent, Outcome, ProcessEvent,
};
use chrono::Utc;
use uuid::Uuid;

use crate::config::ReportConfig;
use crate::context::GuardContext;
use crate::event::Detection;

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

    match detection {
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
    }
}

/// A destination for flushed event batches.
pub trait ReportSink: Send {
    /// Emit one batch. Errors are logged by the caller and never abort the daemon.
    fn emit(&self, batch: &GuardEventBatch) -> anyhow::Result<()>;
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
}

impl NdjsonSink {
    /// Create a sink writing to `path` (parent dirs created on first write).
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ReportSink for NdjsonSink {
    fn emit(&self, batch: &GuardEventBatch) -> anyhow::Result<()> {
        use std::io::Write;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_vec(batch)?;
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(&line)?;
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
        let batch_max = batch_max.max(1);
        Self {
            ctx,
            sinks,
            buffer: Vec::new(),
            batch_max,
            max_buffer: batch_max.saturating_mul(200).max(1000),
        }
    }

    /// Build a reporter from config: stdout (opt) + local NDJSON audit (opt),
    /// plus any caller-injected `extra_sinks` (e.g. the `agentd guard --upload`
    /// analyzer sink). With no sinks at all, falls back to stdout so the daemon is
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
            sinks.push(Box::new(NdjsonSink::new(path.clone())));
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
    /// Events are taken out to build the batch, but if **every** sink fails (a
    /// total outage — e.g. the local audit log *and* the analyzer sink both down)
    /// the events are re-buffered for the next flush instead of being silently
    /// dropped. The re-buffer is bounded by [`Self::max_buffer`] (oldest events
    /// dropped, with a count) so a sustained outage cannot grow memory without
    /// limit. As long as at least one sink (typically the local NDJSON audit)
    /// accepts the batch, it is considered delivered and not re-buffered.
    pub fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let batch = GuardEventBatch {
            batch_id: format!("guard-batch-{}", Uuid::new_v4()),
            collected_at: Utc::now(),
            host_id: self.ctx.host_id.clone(),
            agent_version: self.ctx.agent_version.clone(),
            events: std::mem::take(&mut self.buffer),
        };
        // With no sinks at all there is nothing to retain for; only re-buffer when
        // sinks exist and every one of them failed.
        let mut delivered = self.sinks.is_empty();
        for sink in &self.sinks {
            match sink.emit(&batch) {
                Ok(()) => delivered = true,
                Err(e) => eprintln!("guard: report sink failed: {e}"),
            }
        }
        if !delivered {
            let mut events = batch.events;
            let overflow = events.len().saturating_sub(self.max_buffer);
            if overflow > 0 {
                events.drain(0..overflow);
                eprintln!(
                    "guard: all report sinks down; buffer full, dropped {overflow} oldest event(s)"
                );
            }
            self.buffer = events;
        }
    }
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

    /// A sink that always fails, to exercise the total-outage re-buffer path.
    struct FailSink;
    impl ReportSink for FailSink {
        fn emit(&self, _batch: &GuardEventBatch) -> anyhow::Result<()> {
            anyhow::bail!("sink down")
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
}
