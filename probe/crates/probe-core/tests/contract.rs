//! Backward-compatible contract test via `probe_core::run_scan`.

mod fixture;

use std::path::PathBuf;

use probe_core::run_scan_at;

use fixture::write_minimal_scan_root;

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
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_scan_root(temp.path());

    let report = run_scan_at(temp.path()).expect("scan must succeed");
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
