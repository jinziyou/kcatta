//! The detect → decide → respond → report pipeline (platform-independent).
//!
//! Sensors feed [`Detection`]s in; each is decided, the response applied (with
//! safety vetoes), and the result reported. Critical-severity events flush
//! immediately for near-real-time delivery.

use agent_contract::Severity;

use crate::config::GuardConfig;
use crate::context::GuardContext;
use crate::decide::decide;
use crate::event::Detection;
use crate::report::Reporter;
use crate::respond::Responder;

/// Owns the response engine + reporter and processes one detection at a time.
pub struct Pipeline {
    config: GuardConfig,
    responder: Responder,
    reporter: Reporter,
}

impl Pipeline {
    /// Build a pipeline from config, wiring sinks per [`crate::config::ReportConfig`].
    pub fn new(config: GuardConfig, ctx: GuardContext) -> Self {
        let responder = Responder::new(config.response.clone());
        let reporter = Reporter::from_config(ctx, &config.report);
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
        let critical = detection.severity() == Severity::Critical;
        let action = decide(&detection, &self.config);
        let (action_taken, outcome) = self.responder.apply(&action);
        self.reporter.record(detection, action_taken, outcome);
        if critical {
            self.reporter.flush();
        }
    }

    /// Flush any buffered events (called on the periodic tick and at shutdown).
    pub fn flush(&mut self) {
        self.reporter.flush();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)] // nested-field tweaks read clearer than full literals
    use super::*;
    use crate::config::Mode;
    use crate::report::{NdjsonSink, Reporter};
    use agent_contract::Severity;

    fn ctx() -> GuardContext {
        GuardContext {
            host_id: "h-1".into(),
            agent_version: "0.1.0".into(),
        }
    }

    fn read_one(audit: &std::path::Path) -> serde_json::Value {
        let text = std::fs::read_to_string(audit).unwrap();
        let line = text.lines().next().expect("one batch line");
        serde_json::from_str(line).unwrap()
    }

    /// The safe-by-default contract: even with the quarantine gate ON, monitor
    /// mode performs NO destructive action and reports `action_taken=logged`.
    #[test]
    fn dry_run_default_takes_no_action() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("evil.bin");
        std::fs::write(&target, b"x").unwrap();
        let audit = dir.path().join("audit.ndjson");

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
    #[test]
    fn enforce_quarantines_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("evil.bin");
        std::fs::write(&target, b"x").unwrap();
        let vault = dir.path().join("vault");
        let audit = dir.path().join("audit.ndjson");

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
}
