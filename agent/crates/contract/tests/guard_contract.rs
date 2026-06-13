//! Cross-language contract conformance test for the guard envelope.
//!
//! Validates that a [`GuardEventBatch`] built from the Rust mirror serializes to
//! JSON that conforms to `analyzer/schemas-json/GuardEventBatch.schema.json`
//! (generated from the canonical Pydantic model). This is the drift guard for
//! the real-time protection contract, mirroring `agent-flow`'s FlowBatch test.

use std::path::PathBuf;

use agent_contract::{
    ActionTaken, FileIntegrityEvent, FimChange, FlowProto, GuardEvent, GuardEventBatch, IdsEvent,
    IndicatorType, MalwareEvent, NetworkEvent, Outcome, ProcessEvent, Severity,
};
use chrono::{TimeZone, Utc};

/// Locate the JSON Schema produced by `analyzer-export-schemas`.
///
///     kcatta/
///     ├── analyzer/schemas-json/...
///     └── agent/crates/contract/  <- CARGO_MANIFEST_DIR
fn schema_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../analyzer/schemas-json")
        .join(name)
}

fn load_schema(name: &str) -> serde_json::Value {
    let path = schema_path(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("schema is valid JSON")
}

/// One batch carrying every `GuardEvent` variant so the whole union is exercised.
fn sample_batch() -> GuardEventBatch {
    let ts = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
    GuardEventBatch {
        batch_id: "guard-batch-1".into(),
        collected_at: ts,
        host_id: "host-1".into(),
        agent_version: "0.1.0".into(),
        events: vec![
            GuardEvent::Fim(FileIntegrityEvent {
                event_id: "e-fim".into(),
                timestamp: ts,
                severity: Severity::High,
                host_id: "host-1".into(),
                action_taken: ActionTaken::Logged,
                outcome: Outcome::Success,
                path: "/etc/passwd".into(),
                change_type: FimChange::Modified,
                hash_before: Some("aaa".into()),
                hash_after: Some("bbb".into()),
            }),
            GuardEvent::Malware(MalwareEvent {
                event_id: "e-mal".into(),
                timestamp: ts,
                severity: Severity::Critical,
                host_id: "host-1".into(),
                action_taken: ActionTaken::Quarantined,
                outcome: Outcome::Success,
                path: "/tmp/eicar.com".into(),
                signature: "Eicar-Test-Signature".into(),
                source: "clamav".into(),
                process_id: Some(4242),
            }),
            GuardEvent::Process(ProcessEvent {
                event_id: "e-proc".into(),
                timestamp: ts,
                severity: Severity::Medium,
                host_id: "host-1".into(),
                action_taken: ActionTaken::NoAction,
                outcome: Outcome::Success,
                pid: 1234,
                process_name: "curl".into(),
                behavior: "suspicious_parent".into(),
                rule_id: "R-001".into(),
                evidence: Some("sshd->bash->curl".into()),
                parent_pid: Some(1000),
                parent_name: Some("bash".into()),
            }),
            GuardEvent::Network(NetworkEvent {
                event_id: "e-net".into(),
                timestamp: ts,
                severity: Severity::High,
                host_id: "host-1".into(),
                action_taken: ActionTaken::BlockedConnection,
                outcome: Outcome::Success,
                proto: FlowProto::Tcp,
                src_ip: "10.0.0.2".into(),
                src_port: Some(54321),
                dst_ip: "203.0.113.5".into(),
                dst_port: Some(443),
                indicator: "203.0.113.5".into(),
                indicator_type: IndicatorType::Ip,
                category: "c2".into(),
                source: "abuse.ch-feodo".into(),
            }),
            GuardEvent::Ids(IdsEvent {
                event_id: "e-ids".into(),
                timestamp: ts,
                severity: Severity::High,
                host_id: "host-1".into(),
                action_taken: ActionTaken::BlockedConnection,
                outcome: Outcome::Partial,
                signature_id: "2013028".into(),
                signature_name: "ET MALWARE Generic".into(),
                proto: FlowProto::Tcp,
                src_ip: "10.0.0.2".into(),
                src_port: Some(40000),
                dst_ip: "198.51.100.7".into(),
                dst_port: Some(80),
            }),
        ],
    }
}

#[test]
fn guard_batch_validates_against_schema() {
    let batch = sample_batch();
    let json = serde_json::to_value(&batch).expect("batch serializes");

    let schema = load_schema("GuardEventBatch.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");

    if let Err(error) = validator.validate(&json) {
        panic!(
            "GuardEventBatch output does not match contract:\n  error: {error}\n  payload: {}",
            serde_json::to_string_pretty(&json).unwrap()
        );
    }
}

#[test]
fn malformed_guard_event_is_rejected() {
    // Unknown `action_taken` value must fail (the enum is constrained).
    let bad = serde_json::json!({
        "batch_id": "b-1",
        "collected_at": "2026-06-09T12:00:00Z",
        "host_id": "h-1",
        "agent_version": "0.0.0",
        "events": [{
            "kind": "fim",
            "event_id": "e-1",
            "timestamp": "2026-06-09T12:00:00Z",
            "severity": "high",
            "host_id": "h-1",
            "action_taken": "explode",
            "outcome": "success",
            "path": "/etc/passwd",
            "change_type": "modified",
            "hash_before": null,
            "hash_after": null
        }]
    });

    let schema = load_schema("GuardEventBatch.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");
    assert!(
        validator.validate(&bad).is_err(),
        "unknown action_taken value must fail validation"
    );
}
