//! Cross-language contract conformance tests.
//!
//! Validates that the JSON produced by `scanner-core` conforms to the
//! JSON Schema generated from the canonical Pydantic models living in
//! `form/`. This test is the **single most important** safety net for
//! contract drift between Rust scanner and Python form.

use std::path::PathBuf;

use scanner_core::run_scan;

/// Locate `form/schemas-json/AssetReport.schema.json` from inside the
/// scanner-core crate. The relative layout is fixed by the monorepo:
///
///     cyber-posture/
///     ├── form/schemas-json/...
///     └── scanner/crates/scanner-core/  <- CARGO_MANIFEST_DIR
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
fn scan_output_validates_against_asset_report_schema() {
    let report = run_scan().expect("scan must succeed");
    let json = serde_json::to_value(&report).expect("report serializes");

    let schema = load_schema("AssetReport.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");

    if let Err(error) = validator.validate(&json) {
        panic!(
            "scan() output does not match AssetReport contract:\n  error: {error}\n  payload: {}",
            serde_json::to_string_pretty(&json).unwrap()
        );
    }
}

/// Sanity check: a deliberately malformed report must be rejected.
/// Guards against the schema accidentally being too permissive (e.g. if
/// the wrong JSON Schema dialect were loaded).
#[test]
fn malformed_report_is_rejected() {
    let bad = serde_json::json!({
        "report_id": "r",
        "collected_at": "2026-05-28T10:00:00Z",
        "scanner_version": "0.0.0",
        "host": {
            "host_id": "h",
            "hostname": "x",
            "os": "Linux",
            "kernel": null,
            "arch": null,
            "ip_addrs": [],
            "mac_addrs": [],
            "boot_time": null,
        },
        "assets": [{ "kind": "alien", "asset_id": "a" }],
        "vulnerabilities": [],
    });

    let schema = load_schema("AssetReport.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");
    assert!(
        validator.validate(&bad).is_err(),
        "unknown asset kind must fail validation"
    );
}
