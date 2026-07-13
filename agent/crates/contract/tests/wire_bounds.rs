//! Producer-side regression tests for limits enforced by Form's Pydantic models.

use agent_contract::{
    Asset, AssetReport, GuardEventBatch, HostInfo, Image, Package, ProcessEventType,
    ProcessTraceEvent, Severity, TraceBatch, Vulnerability, CORRELATION_IDENTIFIER_MAX_CHARS,
    NESTED_LIST_MAX_ITEMS, WIRE_STRING_MAX_CHARS,
};
use chrono::Utc;

#[test]
fn optional_form_provenance_defaults_omits_and_is_correlation_bounded() {
    let mut report: AssetReport = serde_json::from_value(serde_json::json!({
        "report_id": "report",
        "collected_at": "2026-07-13T00:00:00Z",
        "scanner_version": "test",
        "host": {
            "host_id": "host",
            "hostname": "host",
            "os": "linux",
            "kernel": null,
            "arch": null,
            "ip_addrs": [],
            "mac_addrs": [],
            "boot_time": null
        },
        "assets": [],
        "vulnerabilities": []
    }))
    .unwrap();
    let mut trace: TraceBatch = serde_json::from_value(serde_json::json!({
        "batch_id": "trace",
        "collected_at": "2026-07-13T00:00:00Z",
        "collector_id": "collector",
        "collector_version": "test",
        "events": []
    }))
    .unwrap();
    let mut guard: GuardEventBatch = serde_json::from_value(serde_json::json!({
        "batch_id": "guard",
        "collected_at": "2026-07-13T00:00:00Z",
        "host_id": "host",
        "agent_version": "test",
        "events": []
    }))
    .unwrap();

    for value in [
        serde_json::to_value(&report).unwrap(),
        serde_json::to_value(&trace).unwrap(),
        serde_json::to_value(&guard).unwrap(),
    ] {
        assert!(value.get("source_agent_id").is_none());
        assert!(value.get("source_target_id").is_none());
    }

    let long_agent = "agent".repeat(100);
    let long_target = "target".repeat(100);
    report.source_agent_id = Some(long_agent.clone());
    report.source_target_id = Some(long_target.clone());
    trace.source_agent_id = Some(long_agent.clone());
    trace.source_target_id = Some(long_target.clone());
    guard.source_agent_id = Some(long_agent);
    guard.source_target_id = Some(long_target);
    report.bound_correlation_ids();
    trace.bound_correlation_ids();
    guard.bound_correlation_ids();

    for (agent_id, target_id) in [
        (&report.source_agent_id, &report.source_target_id),
        (&trace.source_agent_id, &trace.source_target_id),
        (&guard.source_agent_id, &guard.source_target_id),
    ] {
        assert_eq!(
            agent_id.as_deref().unwrap().chars().count(),
            CORRELATION_IDENTIFIER_MAX_CHARS
        );
        assert_eq!(
            target_id.as_deref().unwrap().chars().count(),
            CORRELATION_IDENTIFIER_MAX_CHARS
        );
        assert!(agent_id.as_deref().unwrap().contains("~sha256:"));
        assert!(target_id.as_deref().unwrap().contains("~sha256:"));
    }
}

#[test]
fn host_and_asset_nested_lists_fail_locally_instead_of_becoming_422() {
    let mut host = HostInfo {
        host_id: "host".into(),
        hostname: "host".into(),
        os: "linux".into(),
        kernel: None,
        arch: None,
        ip_addrs: vec!["192.0.2.1".into(); NESTED_LIST_MAX_ITEMS + 1],
        mac_addrs: Vec::new(),
        boot_time: None,
    };
    let error = host.normalize_wire_fields().unwrap_err();
    assert!(error.to_string().contains("host.ip_addrs"));

    let mut image = Asset::Image(Image {
        asset_id: "image-1".into(),
        parent_asset_id: None,
        name: "image".into(),
        runtime: "docker".into(),
        image_id: None,
        tags: vec!["repo:tag".into(); NESTED_LIST_MAX_ITEMS + 1],
        created: None,
    });
    let error = image.normalize_wire_fields().unwrap_err();
    assert!(error.to_string().contains("image.tags"));
}

#[test]
fn vulnerability_references_and_process_argv_fail_locally() {
    let mut vulnerability = Vulnerability {
        vuln_id: "finding".into(),
        severity: Severity::High,
        cvss_score: None,
        affected_asset_id: "host".into(),
        parent_asset_id: None,
        source: "test".into(),
        evidence: None,
        references: vec!["https://example.test".into(); NESTED_LIST_MAX_ITEMS + 1],
    };
    let error = vulnerability.normalize_wire_fields().unwrap_err();
    assert!(error.to_string().contains("vulnerability.references"));

    let process = ProcessTraceEvent {
        trace_id: "trace".into(),
        host_id: "host".into(),
        ts: Utc::now(),
        event_type: ProcessEventType::Exec,
        pid: 1,
        ppid: None,
        uid: None,
        comm: "proc".into(),
        exe: None,
        argv: vec!["arg".into(); NESTED_LIST_MAX_ITEMS + 1],
        cgroup: None,
        exit_code: None,
        threat_intel: Vec::new(),
    };
    let mut batch = TraceBatch {
        batch_id: "batch".into(),
        collected_at: Utc::now(),
        collector_id: "collector".into(),
        collector_version: "test".into(),
        source_agent_id: None,
        source_target_id: None,
        events: Vec::new(),
        file_events: Vec::new(),
        process_events: vec![process],
    };
    batch.normalize_wire_fields().unwrap();
    let error = batch.validate_nested_wire_bounds().unwrap_err();
    assert!(error.to_string().contains("process_trace.argv"));
}

#[test]
fn ordinary_text_is_hashed_but_dedicated_paths_are_not_shortened() {
    let long = "界".repeat(WIRE_STRING_MAX_CHARS + 1);
    let mut package = Asset::Package(Package {
        asset_id: "package-1".into(),
        parent_asset_id: None,
        name: long.clone(),
        version: "1".into(),
        source: None,
        install_path: Some(long.clone()),
        ecosystem: None,
    });

    let error = package.normalize_wire_fields().unwrap_err();
    let Asset::Package(package) = package else {
        unreachable!()
    };
    assert_eq!(package.name.chars().count(), WIRE_STRING_MAX_CHARS);
    assert!(package.name.contains("~sha256:"));
    assert_eq!(package.install_path.as_deref(), Some(long.as_str()));
    assert!(error.to_string().contains("package.install_path"));
}
