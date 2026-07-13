//! The detect → decide → respond → report pipeline (platform-independent).
//!
//! Sensors feed [`Detection`]s in; each is decided, the response applied (with
//! safety vetoes), and the result reported. Critical-severity events flush
//! immediately for near-real-time delivery.

use agent_contract::Severity;

use crate::config::GuardConfig;
use crate::context::GuardContext;
use crate::decide::decide;
use crate::report::Reporter;
use crate::respond::Responder;
use crate::sensors::SensorEvent;
use crate::Detection;

/// Owns the response engine + reporter and processes one detection at a time.
pub struct Pipeline {
    config: GuardConfig,
    responder: Responder,
    reporter: Reporter,
}

impl Pipeline {
    /// Build a pipeline from config, wiring stdout/NDJSON sinks per
    /// [`crate::config::ReportConfig`] plus any caller-injected `extra_sinks`.
    pub fn new(
        config: GuardConfig,
        ctx: GuardContext,
        extra_sinks: Vec<Box<dyn crate::ReportSink>>,
    ) -> Self {
        let responder = Responder::new(config.response.clone());
        let reporter = Reporter::from_config(ctx, &config.report, extra_sinks);
        Self {
            config,
            responder,
            reporter,
        }
    }

    /// Build a pipeline with an explicit reporter (tests).
    #[cfg(test)]
    pub(crate) fn with_reporter(config: GuardConfig, reporter: Reporter) -> Self {
        let responder = Responder::new(config.response.clone());
        Self {
            config,
            responder,
            reporter,
        }
    }

    /// Decide → respond → report one detection.
    pub fn handle(&mut self, detection: Detection) {
        self.handle_sensor_event(detection.into());
    }

    /// Handle a sensor emission, preserving a response already executed inside
    /// a synchronous kernel hook instead of deciding/applying a second action.
    pub(crate) fn handle_sensor_event(&mut self, event: SensorEvent) {
        let critical = event.detection.severity() == Severity::Critical;
        let (action_taken, outcome) = match event.pre_applied {
            Some(result) => result,
            None => {
                let action = decide(&event.detection, &self.config);
                self.responder.apply(&action)
            }
        };
        self.reporter.record(event.detection, action_taken, outcome);
        if critical {
            self.reporter.flush();
        }
    }

    /// Flush any buffered events (called on the periodic tick and at shutdown).
    pub fn flush(&mut self) {
        self.reporter.flush();
    }

    /// Final shutdown flush. Unlike periodic [`Self::flush`], this reports a
    /// total sink outage instead of allowing an in-memory rebuffer to disappear
    /// when the pipeline is destroyed.
    pub(crate) fn finish(&mut self) -> anyhow::Result<()> {
        self.reporter.flush();
        anyhow::ensure!(
            self.reporter.pending() == 0,
            "{} guard event(s) remain unpersisted after final report flush",
            self.reporter.pending()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)] // nested-field tweaks read clearer than full literals
    use super::*;
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
    use crate::config::Mode;
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
    use crate::report::NdjsonSink;
    use crate::report::Reporter;
    use agent_contract::Severity;
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
    use agent_contract::{ActionTaken, Outcome};

    fn ctx() -> GuardContext {
        GuardContext {
            host_id: "h-1".into(),
            agent_version: "0.1.0".into(),
        }
    }

    #[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
    fn read_one(audit: &std::path::Path) -> serde_json::Value {
        let text = std::fs::read_to_string(audit).unwrap();
        let line = text.lines().next().expect("one batch line");
        serde_json::from_str(line).unwrap()
    }

    /// The safe-by-default contract: even with the quarantine gate ON, monitor
    /// mode performs NO destructive action and reports `action_taken=logged`.
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
    #[test]
    fn dry_run_default_takes_no_action() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("evil.bin");
        std::fs::write(&target, b"x").unwrap();
        let audit = dir.path().join("audit-log/audit.ndjson");

        let mut config = GuardConfig::default(); // monitor
        config.response.allow_quarantine = true; // gate on, but monitor must not act

        let reporter =
            Reporter::with_sinks(ctx(), vec![Box::new(NdjsonSink::new(audit.clone()))], 1);
        let mut pipeline = Pipeline::with_reporter(config, reporter);

        pipeline.handle(Detection::Malware {
            severity: Severity::Critical,
            path: target.to_string_lossy().into_owned(),
            signature: "X".into(),
            source: "clamav".into(),
            process_id: None,
        });

        assert!(target.exists(), "monitor mode must not touch the file");
        let v = read_one(&audit);
        assert_eq!(v["events"][0]["action_taken"], "logged");
        assert_eq!(v["events"][0]["outcome"], "success");
        assert_eq!(v["events"][0]["kind"], "malware");
    }

    /// Enforce mode + gate on + a non-system path → the file is quarantined.
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
    #[test]
    fn enforce_quarantines_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("evil.bin");
        std::fs::write(&target, b"x").unwrap();
        let vault = dir.path().join("vault");
        let audit = dir.path().join("audit-log/audit.ndjson");

        let mut config = GuardConfig::default();
        config.mode = Mode::Enforce;
        config.response.allow_quarantine = true;
        config.response.vault_dir = vault.clone();
        config.response.critical_paths.clear();
        config.response.allowlist_paths.clear();

        let reporter =
            Reporter::with_sinks(ctx(), vec![Box::new(NdjsonSink::new(audit.clone()))], 1);
        let mut pipeline = Pipeline::with_reporter(config, reporter);

        pipeline.handle(Detection::Malware {
            severity: Severity::Critical,
            path: target.to_string_lossy().into_owned(),
            signature: "X".into(),
            source: "clamav".into(),
            process_id: None,
        });

        assert!(!target.exists(), "enforce mode quarantined the file");
        let v = read_one(&audit);
        assert_eq!(v["events"][0]["action_taken"], "quarantined");
    }

    #[cfg(all(unix, not(any(target_os = "redox", target_os = "solaris"))))]
    #[test]
    fn pre_applied_block_open_is_reported_without_quarantining_again() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("evil.bin");
        std::fs::write(&target, b"x").unwrap();
        let audit = dir.path().join("audit-log/audit.ndjson");

        let mut config = GuardConfig::default();
        config.mode = Mode::Enforce;
        config.response.allow_block_open = true;
        config.response.allow_quarantine = true;
        config.response.vault_dir = dir.path().join("vault");
        config.response.critical_paths.clear();
        config.response.allowlist_paths.clear();

        let reporter =
            Reporter::with_sinks(ctx(), vec![Box::new(NdjsonSink::new(audit.clone()))], 1);
        let mut pipeline = Pipeline::with_reporter(config, reporter);
        let detection = Detection::Malware {
            severity: Severity::Critical,
            path: target.to_string_lossy().into_owned(),
            signature: "X".into(),
            source: "kcatta-malware".into(),
            process_id: Some(42),
        };

        pipeline.handle_sensor_event(SensorEvent::pre_applied(
            detection,
            ActionTaken::BlockedOpen,
            Outcome::Success,
        ));

        assert!(
            target.exists(),
            "a pre-applied deny must not trigger a second quarantine action"
        );
        let v = read_one(&audit);
        assert_eq!(v["events"][0]["action_taken"], "blocked_open");
        assert_eq!(v["events"][0]["outcome"], "success");
    }

    struct FailSink;

    impl crate::ReportSink for FailSink {
        fn emit(&self, _batch: &agent_contract::GuardEventBatch) -> anyhow::Result<()> {
            anyhow::bail!("sink unavailable")
        }
    }

    #[test]
    fn final_flush_fails_when_every_sink_rebuffers() {
        let reporter = Reporter::with_sinks(ctx(), vec![Box::new(FailSink)], 50);
        let mut pipeline = Pipeline::with_reporter(GuardConfig::default(), reporter);
        pipeline.handle(Detection::Fim {
            severity: Severity::Medium,
            path: "/tmp/test".into(),
            change: agent_contract::FimChange::Modified,
            hash_before: None,
            hash_after: None,
        });

        let error = pipeline
            .finish()
            .expect_err("total sink outage must make shutdown fail");
        assert!(error.to_string().contains("remain unpersisted"));
    }
}
