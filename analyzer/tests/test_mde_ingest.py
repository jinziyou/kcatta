"""MDE cloud batches remain raw-queryable and feed the common alert lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.schemas import MdeAlert, MdeIncident, MdeSecurityBatch, Severity

NOW = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)


def _batch() -> MdeSecurityBatch:
    return MdeSecurityBatch(
        batch_id="mde-sync-test-1",
        collected_at=NOW,
        tenant_id="00000000-0000-0000-0000-000000000001",
        query_started_at=NOW,
        alerts=[
            MdeAlert(
                alert_id="alert-1",
                incident_id="incident-1",
                title="Malware detected",
                description="Microsoft Defender blocked a payload.",
                severity=Severity.HIGH,
                provider_status="new",
                product_name="Microsoft Defender for Endpoint",
                created_at=NOW,
                last_updated_at=NOW,
                related_asset_ids=["host-windows-1"],
                mitre_techniques=["T1204.002"],
            )
        ],
        incidents=[
            MdeIncident(
                incident_id="incident-1",
                display_name="Endpoint malware incident",
                severity=Severity.HIGH,
                provider_status="active",
                created_at=NOW,
                last_updated_at=NOW,
                alert_ids=["alert-1"],
                related_asset_ids=["host-windows-1"],
            )
        ],
    )


def test_mde_batch_is_idempotent_and_visible_as_common_alerts(tmp_path: Path) -> None:
    app = create_app(data_dir=tmp_path, storage_backend="sqlite")
    payload = _batch().model_dump(mode="json")
    with TestClient(app) as client:
        first = client.post("/ingest/mde-security-batch", json=payload)
        duplicate = client.post("/ingest/mde-security-batch", json=payload)
        alerts = client.get("/reports/alerts").json()
        raw = client.get("/reports/mde-security-batches").json()

    assert first.status_code == 202, first.text
    assert first.json()["derived_status"] == "complete"
    assert first.json()["derived_records"] == 2
    assert duplicate.status_code == 202, duplicate.text
    assert duplicate.json()["duplicate"] is True
    assert len(app.state.alert_store.tail(10)) == 2
    assert len(alerts) == 2
    assert {item["title"] for item in alerts} == {
        "[MDE] Malware detected",
        "[MDE Incident] Endpoint malware incident",
    }
    assert all(item["related_asset_ids"] == ["host-windows-1"] for item in alerts)
    assert len(raw) == 1
    assert raw[0]["batch_id"] == "mde-sync-test-1"


def test_mde_resolved_provider_state_closes_common_alert(tmp_path: Path) -> None:
    batch = _batch()
    batch.alerts[0].provider_status = "resolved"
    app = create_app(data_dir=tmp_path)
    with TestClient(app) as client:
        response = client.post(
            "/ingest/mde-security-batch",
            json=batch.model_dump(mode="json"),
        )
        alerts = client.get("/reports/alerts").json()

    assert response.status_code == 202
    alert = next(item for item in alerts if item["title"].startswith("[MDE] "))
    assert alert["status"] == "closed"

