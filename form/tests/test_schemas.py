"""Tests for cyber-posture data contracts.

These tests double as the executable specification of the v0 schema:
if they pass, scanner / collector / portal can rely on the documented
shape.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from form.schemas import (
    Alert,
    AlertStatus,
    AssetReport,
    Credential,
    CredentialKind,
    FlowBatch,
    FlowEvent,
    HostInfo,
    IndicatorType,
    Package,
    Port,
    Service,
    Severity,
    ThreatMatch,
    Vulnerability,
)

NOW = datetime(2026, 5, 28, 10, 0, 0, tzinfo=UTC)


def _sample_report() -> AssetReport:
    return AssetReport(
        report_id="r-001",
        collected_at=NOW,
        scanner_version="0.1.0",
        host=HostInfo(
            host_id="h-001",
            hostname="db-01",
            os="Ubuntu 22.04",
            arch="x86_64",
            ip_addrs=["10.0.0.1"],
        ),
        assets=[
            Package(asset_id="pkg-1", name="openssl", version="3.0.2", source="apt"),
            Service(asset_id="svc-1", name="sshd", status="running"),
            Port(asset_id="port-1", proto="tcp", port=22, listen_addr="0.0.0.0"),
            Credential(
                asset_id="cred-1",
                credential_kind=CredentialKind.SSH_KEY,
                fingerprint="SHA256:abc",
                path="/home/user/.ssh/id_rsa",
            ),
        ],
        vulnerabilities=[
            Vulnerability(
                vuln_id="CVE-2024-0001",
                severity=Severity.HIGH,
                cvss_score=8.1,
                affected_asset_id="pkg-1",
                source="trivy",
            )
        ],
    )


class TestRoundTrip:
    def test_asset_report_round_trip(self):
        original = _sample_report()
        data = original.model_dump(mode="json")
        revived = AssetReport.model_validate(data)
        assert revived == original

    def test_flow_batch_round_trip(self):
        batch = FlowBatch(
            batch_id="b-1",
            collected_at=NOW,
            collector_id="col-1",
            collector_version="0.1.0",
            flows=[
                FlowEvent(
                    flow_id="f-1",
                    host_id="h-001",
                    start_ts=NOW,
                    end_ts=NOW,
                    proto="tcp",
                    src_ip="10.0.0.1",
                    src_port=12345,
                    dst_ip="93.184.216.34",
                    dst_port=443,
                    bytes_sent=512,
                    bytes_recv=2048,
                    app_proto="TLS",
                    tls_sni="example.com",
                )
            ],
        )
        data = batch.model_dump(mode="json")
        revived = FlowBatch.model_validate(data)
        assert revived == batch

    def test_flow_event_defaults_to_no_threat_intel(self):
        flow = FlowEvent(
            flow_id="f-1",
            host_id="h-001",
            start_ts=NOW,
            end_ts=NOW,
            proto="tcp",
            src_ip="10.0.0.1",
            dst_ip="93.184.216.34",
            bytes_sent=1,
            bytes_recv=1,
        )
        assert flow.threat_intel == []

    def test_flow_event_with_threat_intel_round_trip(self):
        flow = FlowEvent(
            flow_id="f-1",
            host_id="h-001",
            start_ts=NOW,
            end_ts=NOW,
            proto="tcp",
            src_ip="10.0.0.1",
            dst_ip="93.184.216.34",
            dst_port=443,
            bytes_sent=512,
            bytes_recv=2048,
            tls_sni="evil.example.com",
            threat_intel=[
                ThreatMatch(
                    indicator="93.184.216.34",
                    indicator_type=IndicatorType.IP,
                    category="c2",
                    severity=Severity.HIGH,
                    source="builtin-demo",
                    description="Known C2 node",
                )
            ],
        )
        data = flow.model_dump(mode="json")
        revived = FlowEvent.model_validate(data)
        assert revived == flow
        assert revived.threat_intel[0].indicator_type == IndicatorType.IP

    def test_alert_round_trip(self):
        alert = Alert(
            alert_id="a-1",
            severity=Severity.HIGH,
            score=85.0,
            title="Outbound traffic to known C2",
            description="db-01 contacted 93.184.216.34:443 matching threat intel",
            related_asset_ids=["h-001"],
            related_flow_ids=["f-1"],
            created_at=NOW,
        )
        assert alert.status == AlertStatus.OPEN
        data = alert.model_dump(mode="json")
        revived = Alert.model_validate(data)
        assert revived == alert


class TestStrictness:
    def test_extra_field_rejected(self):
        with pytest.raises(ValidationError):
            Vulnerability(
                vuln_id="CVE-1",
                severity=Severity.LOW,
                affected_asset_id="x",
                source="s",
                unknown_field="boom",
            )

    def test_port_out_of_range(self):
        with pytest.raises(ValidationError):
            Port(asset_id="p", proto="tcp", port=70000, listen_addr="0.0.0.0")

    def test_cvss_out_of_range(self):
        with pytest.raises(ValidationError):
            Vulnerability(
                vuln_id="CVE-1",
                severity=Severity.LOW,
                cvss_score=11.0,
                affected_asset_id="x",
                source="s",
            )

    def test_alert_score_out_of_range(self):
        with pytest.raises(ValidationError):
            Alert(
                alert_id="a",
                severity=Severity.LOW,
                score=150.0,
                title="t",
                description="d",
                created_at=NOW,
            )


class TestAssetDiscriminator:
    def test_validates_each_kind(self):
        report = _sample_report()
        json_data = report.model_dump(mode="json")
        revived = AssetReport.model_validate(json_data)
        kinds = [a.kind for a in revived.assets]
        assert kinds == ["package", "service", "port", "credential"]

    def test_unknown_kind_rejected(self):
        bad = {
            "report_id": "r",
            "collected_at": NOW.isoformat(),
            "scanner_version": "0.1.0",
            "host": {
                "host_id": "h",
                "hostname": "x",
                "os": "Linux",
            },
            "assets": [{"kind": "alien", "asset_id": "a"}],
            "vulnerabilities": [],
        }
        with pytest.raises(ValidationError):
            AssetReport.model_validate(bad)


class TestJsonSchemaExport:
    def test_envelopes_generate_schemas(self):
        for model in (AssetReport, FlowBatch, Alert):
            schema = model.model_json_schema()
            assert schema["title"] == model.__name__
            assert "properties" in schema
