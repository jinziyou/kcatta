"""MDVM snapshots feed existing asset and vulnerability reports idempotently."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.schemas import (
    MdvmDeviceSnapshot,
    MdvmSoftwareVulnerability,
    MdvmVulnerabilityBatch,
    Severity,
)

NOW = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)


def _batch(*, empty: bool = False) -> MdvmVulnerabilityBatch:
    findings = []
    if not empty:
        findings.append(
            MdvmSoftwareVulnerability(
                record_id="record-1",
                cve_id="CVE-2026-12345",
                software_vendor="contoso",
                software_name="browser",
                software_version="1.2.3",
                severity=Severity.HIGH,
                cvss_score=8.1,
                exploitability_level="ExploitIsPublic",
                recommended_security_update="July security update",
                recommended_security_update_id="KB12345",
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        )
    return MdvmVulnerabilityBatch(
        batch_id="mdvm-sync-test-empty" if empty else "mdvm-sync-test-1",
        collected_at=NOW,
        tenant_id="00000000-0000-0000-0000-000000000001",
        mode="delta",
        snapshots=[
            MdvmDeviceSnapshot(
                report_id="mdvm-report-empty" if empty else "mdvm-report-1",
                device_id="device-1",
                host_id="host-windows-1",
                device_name="win-1.contoso.test",
                os_platform="Windows11",
                os_version="24H2",
                os_architecture="x64",
                observed_at=NOW,
                vulnerabilities=findings,
            )
        ],
    )


def test_mdvm_batch_derives_asset_and_complete_detection(tmp_path: Path) -> None:
    app = create_app(data_dir=tmp_path, storage_backend="sqlite")
    payload = _batch().model_dump(mode="json")
    with TestClient(app) as client:
        first = client.post("/ingest/mdvm-vulnerability-batch", json=payload)
        duplicate = client.post("/ingest/mdvm-vulnerability-batch", json=payload)
        report = client.get("/reports/asset-reports/mdvm-report-1")
        detection = client.get("/reports/vulnerabilities/mdvm-report-1")
        raw = client.get("/reports/mdvm-vulnerability-batches")

    assert first.status_code == 202, first.text
    assert first.json()["derived_status"] == "complete"
    assert first.json()["derived_records"] == 2
    assert duplicate.status_code == 202
    assert duplicate.json()["duplicate"] is True
    assert len(app.state.asset_report_store.tail(10)) == 1
    assert len(app.state.vulnerability_store.tail(10)) == 1
    assert report.status_code == 200
    assert report.json()["assets"][0]["source"] == "mdvm"
    assert detection.status_code == 200
    body = detection.json()
    assert body["detection_status"] == "complete"
    assert body["coverage"][0]["ecosystem"] == "mdvm"
    assert body["vulnerabilities"][0]["source"] == (
        "microsoft-defender-vulnerability-management"
    )
    assert raw.status_code == 200
    assert raw.json()[0]["batch_id"] == "mdvm-sync-test-1"


def test_mdvm_fixed_last_finding_creates_complete_empty_snapshot(tmp_path: Path) -> None:
    app = create_app(data_dir=tmp_path)
    batch = _batch(empty=True)
    with TestClient(app) as client:
        response = client.post(
            "/ingest/mdvm-vulnerability-batch",
            json=batch.model_dump(mode="json"),
        )
        detection = client.get("/reports/vulnerabilities/mdvm-report-empty")

    assert response.status_code == 202
    assert detection.status_code == 200
    assert detection.json()["detection_status"] == "complete"
    assert detection.json()["vulnerabilities"] == []

