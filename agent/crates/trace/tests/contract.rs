//! Cross-language contract conformance tests.
//!
//! Validates that the JSON produced by `agent-trace` conforms to the
//! JSON Schema generated from the canonical Pydantic models living in
//! `analyzer/`. This test is the single most important safety net against
//! contract drift between Rust collector and Python analyzer.

use std::path::PathBuf;

use agent_trace::run_capture;

/// Locate the JSON Schema produced by `analyzer-export-schemas`.
///
///     kcatta/
///     ├── analyzer/schemas-json/...
///     └── agent/crates/trace/  <- CARGO_MANIFEST_DIR
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

#[test]
fn capture_output_validates_against_trace_batch_schema() {
    let batch = run_capture().expect("capture must succeed");
    let json = serde_json::to_value(&batch).expect("batch serializes");

    let schema = load_schema("TraceBatch.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");

    if let Err(error) = validator.validate(&json) {
        panic!(
            "run_capture() output does not match TraceBatch contract:\n  error: {error}\n  payload: {}",
            serde_json::to_string_pretty(&json).unwrap()
        );
    }
}

/// A fully-populated batch — network + file + process events — must validate.
/// Locks the cross-language conformance of the eBPF file/process event types
/// (the capture path above only exercises the empty network stream).
#[test]
fn file_and_process_events_validate_against_schema() {
    use agent_contract::{FileOp, FileTraceEvent, ProcessEventType, ProcessTraceEvent, TraceBatch};
    use chrono::Utc;

    let batch = TraceBatch {
        batch_id: "b-1".into(),
        collected_at: Utc::now(),
        collector_id: "col-1".into(),
        collector_version: "0.0.0".into(),
        events: Vec::new(),
        file_events: vec![FileTraceEvent {
            trace_id: "f-1".into(),
            host_id: "h-1".into(),
            ts: Utc::now(),
            pid: 1234,
            comm: "bash".into(),
            uid: Some(0),
            op: FileOp::Open,
            path: "/etc/shadow".into(),
            target_path: None,
            ret: Some(3),
            threat_intel: Vec::new(),
        }],
        process_events: vec![ProcessTraceEvent {
            trace_id: "p-1".into(),
            host_id: "h-1".into(),
            ts: Utc::now(),
            event_type: ProcessEventType::Exec,
            pid: 1234,
            ppid: Some(1),
            uid: Some(0),
            comm: "curl".into(),
            exe: Some("/usr/bin/curl".into()),
            argv: vec!["curl".into(), "http://evil.example".into()],
            cgroup: Some("docker-abc".into()),
            exit_code: None,
            threat_intel: Vec::new(),
        }],
    };

    let json = serde_json::to_value(&batch).expect("batch serializes");
    let schema = load_schema("TraceBatch.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");
    if let Err(error) = validator.validate(&json) {
        panic!(
            "file/process TraceBatch does not match contract:\n  error: {error}\n  payload: {}",
            serde_json::to_string_pretty(&json).unwrap()
        );
    }
}

/// Sanity check: a deliberately malformed batch must be rejected.
/// Catches the schema accidentally being too permissive (e.g. wrong
/// dialect loaded) and confirms the validator is actually enforcing
/// the contract.
#[test]
fn malformed_batch_is_rejected() {
    let bad = serde_json::json!({
        "batch_id": "b-1",
        "collected_at": "2026-05-28T10:00:00Z",
        "collector_id": "col-1",
        "collector_version": "0.0.0",
        "events": [{
            "trace_id": "f-1",
            "host_id": "h-1",
            "start_ts": "2026-05-28T10:00:00Z",
            "end_ts": "2026-05-28T10:00:01Z",
            "proto": "xyz",
            "src_ip": "10.0.0.1",
            "src_port": null,
            "dst_ip": "10.0.0.2",
            "dst_port": null,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "packets_sent": 0,
            "packets_recv": 0,
            "app_proto": null,
            "dns_query": null,
            "tls_sni": null,
            "ja3": null,
        }],
    });

    let schema = load_schema("TraceBatch.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");
    assert!(
        validator.validate(&bad).is_err(),
        "unknown proto value must fail validation"
    );
}
