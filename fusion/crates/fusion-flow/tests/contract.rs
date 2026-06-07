//! Cross-language contract conformance tests.
//!
//! Validates that the JSON produced by `fusion-flow` conforms to the
//! JSON Schema generated from the canonical Pydantic models living in
//! `form/`. This test is the single most important safety net against
//! contract drift between Rust collector and Python form.

use std::path::PathBuf;

use fusion_flow::run_capture;

/// Locate the JSON Schema produced by `form-export-schemas`.
///
///     posture/
///     ├── form/schemas-json/...
///     └── collector/crates/fusion-flow/  <- CARGO_MANIFEST_DIR
fn schema_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../form/schemas-json")
        .join(name)
}

fn load_schema(name: &str) -> serde_json::Value {
    let path = schema_path(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("schema is valid JSON")
}

#[test]
fn capture_output_validates_against_flow_batch_schema() {
    let batch = run_capture().expect("capture must succeed");
    let json = serde_json::to_value(&batch).expect("batch serializes");

    let schema = load_schema("FlowBatch.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");

    if let Err(error) = validator.validate(&json) {
        panic!(
            "run_capture() output does not match FlowBatch contract:\n  error: {error}\n  payload: {}",
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
        "flows": [{
            "flow_id": "f-1",
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

    let schema = load_schema("FlowBatch.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");
    assert!(
        validator.validate(&bad).is_err(),
        "unknown proto value must fail validation"
    );
}
