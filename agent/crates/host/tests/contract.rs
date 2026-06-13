//! Cross-language contract conformance tests.
//!
//! Validates that the JSON produced by `agent-host`'s library conforms to
//! the JSON Schema generated from the canonical Pydantic models in `analyzer/`.

mod fixture;

use std::path::PathBuf;

use agent_host::{default_collectors, run_scan_at};

use fixture::write_minimal_scan_root;

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
fn scan_output_validates_against_asset_report_schema() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_scan_root(temp.path());

    let collectors = default_collectors();
    let report = run_scan_at(&collectors, temp.path()).expect("scan must succeed");
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

#[test]
fn all_asset_variants_validate_against_schema() {
    // The minimal-fixture scan only emits `package` assets, so the
    // service/port/account/credential discriminator branches were never
    // exercised against the schema. Build a report containing every asset
    // variant (and a vulnerability) so a drift in any branch is caught here.
    use agent_contract::{
        Account, Asset, AssetReport, Credential, CredentialKind, HostInfo, Package, Port,
        PortProto, Service, Severity, Vulnerability,
    };
    use chrono::Utc;

    let now = Utc::now();
    let report = AssetReport {
        report_id: "r-all".to_string(),
        collected_at: now,
        scanner_version: "0.1.0".to_string(),
        host: HostInfo {
            host_id: "h-1".to_string(),
            hostname: "host".to_string(),
            os: "Ubuntu 22.04".to_string(),
            kernel: Some("6.6.0".to_string()),
            arch: Some("x86_64".to_string()),
            ip_addrs: vec!["10.0.0.1".to_string()],
            mac_addrs: vec!["00:11:22:33:44:55".to_string()],
            boot_time: Some(now),
        },
        assets: vec![
            Asset::Package(Package {
                asset_id: "pkg-1".to_string(),
                name: "openssl".to_string(),
                version: "3.0.2".to_string(),
                source: Some("dpkg".to_string()),
                install_path: Some("/usr/bin/openssl".to_string()),
                ecosystem: Some("Debian:12".to_string()),
            }),
            Asset::Service(Service {
                asset_id: "svc-1".to_string(),
                name: "sshd".to_string(),
                status: "enabled".to_string(),
                exec_path: Some("/usr/sbin/sshd".to_string()),
            }),
            Asset::Port(Port {
                asset_id: "port-1".to_string(),
                proto: PortProto::Tcp,
                port: 443,
                listen_addr: "0.0.0.0".to_string(),
                process_name: Some("nginx".to_string()),
                pid: Some(1234),
            }),
            Asset::Account(Account {
                asset_id: "acct-1".to_string(),
                username: "root".to_string(),
                uid: Some(0),
                shell: Some("/bin/bash".to_string()),
                last_login: Some(now),
            }),
            Asset::Credential(Credential {
                asset_id: "cred-1".to_string(),
                credential_kind: CredentialKind::SshKey,
                fingerprint: "SHA256:abc".to_string(),
                path: Some("/root/.ssh/authorized_keys".to_string()),
                owner: Some("root".to_string()),
            }),
        ],
        vulnerabilities: vec![Vulnerability {
            vuln_id: "Eicar-Test-Signature".to_string(),
            severity: Severity::Critical,
            cvss_score: Some(9.8),
            affected_asset_id: "h-1".to_string(),
            source: "clamav".to_string(),
            evidence: Some("infected file: /tmp/eicar.com".to_string()),
            references: vec!["https://example.test/eicar".to_string()],
        }],
    };

    let json = serde_json::to_value(&report).expect("report serializes");
    let schema = load_schema("AssetReport.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");
    if let Err(error) = validator.validate(&json) {
        panic!(
            "all-variants report does not match AssetReport contract:\n  error: {error}\n  payload: {}",
            serde_json::to_string_pretty(&json).unwrap()
        );
    }
}

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
