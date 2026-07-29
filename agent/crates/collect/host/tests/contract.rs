//! Cross-language contract conformance tests.
//!
//! Validates that the JSON produced by `agent-collect-host`'s library conforms to
//! the JSON Schema generated from the canonical Pydantic models in `analyzer/`.

mod fixture;

use std::path::PathBuf;

use agent_collect_host::{default_collectors, run_scan_at};

use fixture::write_minimal_scan_root;

fn schema_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../form/schemas-json")
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
    assert!(json.get("source_agent_id").is_none());
    assert!(json.get("source_target_id").is_none());

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
fn long_secret_path_and_host_id_validate_against_form_schema() {
    use agent_contract::CORRELATION_IDENTIFIER_MAX_CHARS;
    use agent_detect::host::{detect, DetectOptions};

    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_scan_root(temp.path());
    // Host names are unconstrained input; the derived correlation id must be
    // bounded without shortening the human-readable hostname itself.
    let hostname = "host".repeat(100);
    std::fs::write(temp.path().join("etc/hostname"), format!("{hostname}\n")).unwrap();

    let mut directory = temp.path().to_path_buf();
    for index in 0..10 {
        directory.push(format!("segment-{index:02}-{}", "x".repeat(28)));
    }
    std::fs::create_dir_all(&directory).unwrap();
    let secret_path = directory.join("credentials.conf");
    let token = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].concat();
    std::fs::write(&secret_path, format!("token='{token}'\n")).unwrap();

    let collectors = default_collectors();
    let mut report = run_scan_at(&collectors, temp.path()).expect("scan must succeed");
    let findings = detect(
        temp.path(),
        &report.host.host_id,
        &DetectOptions {
            secrets: true,
            ..DetectOptions::default()
        },
    )
    .expect("secret detection must succeed");
    assert_eq!(
        findings.len(),
        1,
        "the real long-path secret must be detected"
    );

    let finding = &findings[0];
    assert_eq!(
        finding.vuln_id.chars().count(),
        CORRELATION_IDENTIFIER_MAX_CHARS
    );
    assert!(finding.vuln_id.contains("~sha256:"));
    assert!(report.host.host_id.chars().count() <= CORRELATION_IDENTIFIER_MAX_CHARS);
    assert!(report.host.host_id.contains("~sha256:"));

    let relative_path = secret_path
        .strip_prefix(temp.path())
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    assert!(relative_path.chars().count() > CORRELATION_IDENTIFIER_MAX_CHARS);
    assert!(
        finding
            .evidence
            .as_deref()
            .is_some_and(|evidence| evidence.contains(&format!("path={relative_path}"))),
        "the wider evidence/path field must not be truncated"
    );
    assert!(!finding.evidence.as_deref().unwrap().contains(&token));

    report.host.ip_addrs.push("地址".repeat(200));
    report.host.mac_addrs.push("网卡".repeat(200));
    report.vulnerabilities.extend(findings);
    report.bound_correlation_ids();
    assert!(report
        .host
        .ip_addrs
        .iter()
        .chain(&report.host.mac_addrs)
        .all(|address| address.chars().count() <= CORRELATION_IDENTIFIER_MAX_CHARS));
    let json = serde_json::to_value(&report).expect("report serializes");
    let schema = load_schema("AssetReport.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("compile schema");
    if let Err(error) = validator.validate(&json) {
        panic!(
            "long-path detect output does not match Form AssetReport contract:\n  error: {error}\n  payload: {}",
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
        PortProto, SecurityProduct, Service, Severity, Vulnerability,
    };
    use chrono::Utc;

    let now = Utc::now();
    let report = AssetReport {
        report_id: "r-all".to_string(),
        collected_at: now,
        scanner_version: "0.1.0".to_string(),
        source_agent_id: Some("agent-1".to_string()),
        source_target_id: Some("target-1".to_string()),
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
                parent_asset_id: None,
                name: "openssl".to_string(),
                version: "3.0.2".to_string(),
                source: Some("dpkg".to_string()),
                source_name: Some("openssl".to_string()),
                source_version: Some("3.0.2".to_string()),
                install_path: Some("/usr/bin/openssl".to_string()),
                ecosystem: Some("Debian:12".to_string()),
            }),
            Asset::Service(Service {
                asset_id: "svc-1".to_string(),
                parent_asset_id: None,
                name: "sshd".to_string(),
                status: "enabled".to_string(),
                exec_path: Some("/usr/sbin/sshd".to_string()),
            }),
            Asset::Port(Port {
                asset_id: "port-1".to_string(),
                parent_asset_id: None,
                proto: PortProto::Tcp,
                port: 443,
                listen_addr: "0.0.0.0".to_string(),
                process_name: Some("nginx".to_string()),
                pid: Some(1234),
            }),
            Asset::Account(Account {
                asset_id: "acct-1".to_string(),
                parent_asset_id: None,
                username: "root".to_string(),
                uid: Some(0),
                shell: Some("/bin/bash".to_string()),
                last_login: Some(now),
            }),
            Asset::Credential(Credential {
                asset_id: "cred-1".to_string(),
                parent_asset_id: None,
                credential_kind: CredentialKind::SshKey,
                fingerprint: "SHA256:abc".to_string(),
                path: Some("/root/.ssh/authorized_keys".to_string()),
                owner: Some("root".to_string()),
            }),
            Asset::SecurityProduct(SecurityProduct {
                asset_id: "security-product-defender".to_string(),
                parent_asset_id: None,
                name: "Microsoft Defender Antivirus".to_string(),
                vendor: "Microsoft".to_string(),
                status: "active".to_string(),
                mode: Some("Normal".to_string()),
                product_version: Some("4.18.26010.1".to_string()),
                engine_version: Some("1.1.26010.1".to_string()),
                signature_version: Some("1.455.1.0".to_string()),
                signature_updated_at: Some(now),
                signatures_out_of_date: Some(false),
                real_time_protection: Some(true),
                behavior_monitor: Some(true),
                ioav_protection: Some(true),
                tamper_protection: Some(true),
                cloud_protection: Some(true),
                last_quick_scan_at: Some(now),
                last_full_scan_at: None,
            }),
        ],
        vulnerabilities: vec![Vulnerability {
            vuln_id: "Eicar-Test-Signature".to_string(),
            severity: Severity::Critical,
            cvss_score: Some(9.8),
            affected_asset_id: "h-1".to_string(),
            parent_asset_id: None,
            source: "clamav".to_string(),
            evidence: Some("infected file: /tmp/eicar.com".to_string()),
            references: vec!["https://example.test/eicar".to_string()],
        }],
        detector_runs: None,
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
