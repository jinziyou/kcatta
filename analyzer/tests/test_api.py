"""Integration tests for the analyzer HTTP API.

These exercise the full request -> Pydantic validation -> persistence
path with FastAPI's TestClient, redirecting writes to a pytest
``tmp_path`` so each test gets a clean filesystem.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.schemas import AssetReport
from analyzer.storage import StorageCapacityError

NOW = datetime(2026, 5, 28, 10, 0, 0, tzinfo=UTC)


def _sample_asset_report() -> dict:
    return {
        "report_id": "r-001",
        "collected_at": NOW.isoformat(),
        "scanner_version": "0.1.0",
        "host": {
            "host_id": "h-001",
            "hostname": "db-01",
            "os": "Ubuntu 22.04",
            "kernel": None,
            "arch": "x86_64",
            "ip_addrs": ["10.0.0.1"],
            "mac_addrs": [],
            "boot_time": None,
        },
        "assets": [
            {
                "kind": "package",
                "asset_id": "pkg-1",
                "name": "openssl",
                "version": "3.0.2",
                "source": "apt",
                "install_path": None,
            }
        ],
        "vulnerabilities": [],
    }


def _sample_trace_batch() -> dict:
    return {
        "batch_id": "b-1",
        "collected_at": NOW.isoformat(),
        "collector_id": "col-1",
        "collector_version": "0.1.0",
        "events": [
            {
                "trace_id": "f-1",
                "host_id": "h-001",
                "start_ts": NOW.isoformat(),
                "end_ts": NOW.isoformat(),
                "proto": "tcp",
                "src_ip": "10.0.0.1",
                "src_port": 12345,
                "dst_ip": "93.184.216.34",
                "dst_port": 443,
                "bytes_sent": 512,
                "bytes_recv": 2048,
                "packets_sent": 6,
                "packets_recv": 8,
                "app_proto": "TLS",
                "dns_query": None,
                "tls_sni": "example.com",
                "ja3": None,
            }
        ],
    }


def _sample_guard_batch() -> dict:
    return {
        "batch_id": "g-1",
        "collected_at": NOW.isoformat(),
        "host_id": "h-001",
        "agent_version": "0.1.0",
        "events": [
            {
                "kind": "fim",
                "event_id": "e-fim",
                "timestamp": NOW.isoformat(),
                "severity": "high",
                "host_id": "h-001",
                "action_taken": "logged",
                "outcome": "success",
                "path": "/etc/passwd",
                "change_type": "modified",
                "hash_before": "aaa",
                "hash_after": "bbb",
            },
            {
                "kind": "network",
                "event_id": "e-net",
                "timestamp": NOW.isoformat(),
                "severity": "high",
                "host_id": "h-001",
                "action_taken": "blocked_connection",
                "outcome": "success",
                "proto": "tcp",
                "src_ip": "10.0.0.2",
                "src_port": 54321,
                "dst_ip": "203.0.113.5",
                "dst_port": 443,
                "indicator": "203.0.113.5",
                "indicator_type": "ip",
                "category": "c2",
                "source": "abuse.ch-feodo",
            },
        ],
    }


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(data_dir=tmp_path)
    with TestClient(app) as test_client:
        yield test_client, app


class TestBodySizeLimit:
    def test_oversized_body_rejected_with_413(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ANALYZER_MAX_BODY_BYTES", "1024")
        app = create_app(data_dir=tmp_path)
        with TestClient(app) as c:
            oversized = b'{"x":"' + b"a" * 5000 + b'"}'
            resp = c.post(
                "/ingest/asset-report",
                content=oversized,
                headers={"content-type": "application/json"},
            )
            assert resp.status_code == 413, resp.text

    def test_normal_body_allowed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ANALYZER_MAX_BODY_BYTES", "1048576")
        app = create_app(data_dir=tmp_path)
        with TestClient(app) as c:
            resp = c.post("/ingest/asset-report", json=_sample_asset_report())
            assert resp.status_code == 202, resp.text


class TestStorageCapacity:
    def test_primary_ingest_returns_retryable_507_and_releases_dedup(self, client):
        test_client, app = client

        class FullStore:
            def append(self, _record):
                raise StorageCapacityError("test quota exhausted")

        app.state.asset_report_store = FullStore()
        for _ in range(2):
            response = test_client.post("/ingest/asset-report", json=_sample_asset_report())
            assert response.status_code == 507
            assert response.headers["retry-after"] == "60"
            assert response.json()["detail"] == "Analyzer durable storage capacity is exhausted"


def test_analyzer_requires_internal_token_unless_local_mode_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("ANALYZER_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "false")
    with pytest.raises(RuntimeError, match="ANALYZER_INTERNAL_TOKEN is required"):
        create_app(data_dir=tmp_path)


class TestHealth:
    def test_health_endpoint(self, client):
        c, _ = client
        resp = c.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestIngestAssetReport:
    def test_accepts_valid_report(self, client):
        c, app = client
        resp = c.post("/ingest/asset-report", json=_sample_asset_report())
        assert resp.status_code == 202, resp.text
        assert resp.json()["accepted"] is True
        assert resp.json()["id"] == "r-001"
        assert resp.json()["derived_status"] == "partial"
        assert resp.json()["derived_reason"] == "osv_store_empty"

        stored = app.state.asset_report_store.tail(1)[0]
        assert stored["report_id"] == "r-001"
        assert stored["assets"][0]["kind"] == "package"

    def test_unknown_wire_fields_are_rejected_not_silently_dropped(self, client):
        # The persisted/read model remains lenient for rolling upgrades, but the
        # ingest trust boundary must never acknowledge data it discarded.
        c, app = client
        payload = _sample_asset_report()
        payload["surprise_from_newer_agent"] = "boom"
        payload["host"]["future_host_field"] = "x"
        resp = c.post("/ingest/asset-report", json=payload)
        assert resp.status_code == 422, resp.text
        assert app.state.asset_report_store.tail(1) == []

    def test_rejects_unknown_asset_kind(self, client):
        c, _ = client
        payload = _sample_asset_report()
        payload["assets"] = [{"kind": "alien", "asset_id": "a"}]
        resp = c.post("/ingest/asset-report", json=payload)
        assert resp.status_code == 422

    def test_appends_multiple_reports(self, client):
        c, app = client
        first = _sample_asset_report()
        second = _sample_asset_report()
        second["report_id"] = "r-002"

        assert c.post("/ingest/asset-report", json=first).status_code == 202
        assert c.post("/ingest/asset-report", json=second).status_code == 202

        stored = app.state.asset_report_store.tail(10)
        assert len(stored) == 2
        assert {row["report_id"] for row in stored} == {"r-001", "r-002"}


class TestReadAssetReports:
    def test_get_single_report(self, client):
        c, _ = client
        c.post("/ingest/asset-report", json=_sample_asset_report())
        resp = c.get("/reports/asset-reports/r-001")
        assert resp.status_code == 200
        assert resp.json()["report_id"] == "r-001"

    def test_get_missing_report_returns_404(self, client):
        c, _ = client
        assert c.get("/reports/asset-reports/missing").status_code == 404

    def test_read_tolerates_historical_record_with_extra_fields(self, client):
        # B3 read path: a record persisted by a newer/older analyzer that carries
        # a field this version's response_model does not declare must NOT 500 the
        # whole /reports page. The extra field is dropped on serialization.
        import json

        c, app = client
        payload = _sample_asset_report()
        payload["legacy_only_field"] = {"nested": "value"}
        payload["host"]["legacy_host_field"] = "x"
        store = app.state.asset_report_store
        # Write the historical record straight to the backing store, bypassing
        # the ingest model, to simulate data on disk from another schema version.
        store.path.parent.mkdir(parents=True, exist_ok=True)
        with store.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")

        listed = c.get("/reports/asset-reports")
        assert listed.status_code == 200, listed.text
        assert listed.json()[0]["report_id"] == "r-001"
        one = c.get("/reports/asset-reports/r-001")
        assert one.status_code == 200, one.text
        assert "legacy_only_field" not in one.json()

    def test_empty_when_no_uploads(self, client):
        c, _ = client
        resp = c.get("/reports/asset-reports")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_uploaded_reports_newest_first(self, client):
        c, _ = client
        first = _sample_asset_report()
        second = _sample_asset_report()
        second["report_id"] = "r-002"

        c.post("/ingest/asset-report", json=first)
        c.post("/ingest/asset-report", json=second)

        resp = c.get("/reports/asset-reports")
        assert resp.status_code == 200
        ids = [r["report_id"] for r in resp.json()]
        assert ids == ["r-002", "r-001"], "newest first"

    def test_limit_clamps_result_count(self, client):
        c, _ = client
        for i in range(3):
            payload = _sample_asset_report()
            payload["report_id"] = f"r-{i:03d}"
            c.post("/ingest/asset-report", json=payload)

        resp = c.get("/reports/asset-reports", params={"limit": 2})
        assert resp.status_code == 200
        ids = [r["report_id"] for r in resp.json()]
        assert ids == ["r-002", "r-001"]

    def test_invalid_limit_rejected(self, client):
        c, _ = client
        assert c.get("/reports/asset-reports", params={"limit": 0}).status_code == 422
        assert c.get("/reports/asset-reports", params={"limit": 1000}).status_code == 422


class TestReadTraceBatches:
    def test_empty_when_no_uploads(self, client):
        c, _ = client
        resp = c.get("/reports/trace-batches")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_uploaded_batches_newest_first(self, client):
        c, _ = client
        first = _sample_trace_batch()
        second = _sample_trace_batch()
        second["batch_id"] = "b-2"
        c.post("/ingest/trace-batch", json=first)
        c.post("/ingest/trace-batch", json=second)

        resp = c.get("/reports/trace-batches")
        ids = [b["batch_id"] for b in resp.json()]
        assert ids == ["b-2", "b-1"]


class TestInternalHttpBoundary:
    def test_does_not_expose_browser_cors(self, tmp_path):
        app = create_app(data_dir=tmp_path)
        with TestClient(app) as c:
            resp = c.options(
                "/health",
                headers={
                    "Origin": "http://localhost:10063",
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert resp.status_code == 405
            assert "access-control-allow-origin" not in resp.headers


class TestIngestTraceBatch:
    def test_accepts_valid_batch(self, client):
        c, app = client
        resp = c.post("/ingest/trace-batch", json=_sample_trace_batch())
        assert resp.status_code == 202, resp.text
        assert resp.json()["accepted"] is True
        assert resp.json()["id"] == "b-1"
        assert resp.json()["derived_status"] == "complete"

        stored = app.state.trace_batch_store.tail(1)[0]
        assert stored["batch_id"] == "b-1"
        assert stored["events"][0]["proto"] == "tcp"

    def test_rejects_invalid_proto(self, client):
        c, _ = client
        payload = _sample_trace_batch()
        payload["events"][0]["proto"] = "xyz"
        resp = c.post("/ingest/trace-batch", json=payload)
        assert resp.status_code == 422

    def test_rejects_unknown_nested_trace_field(self, client):
        c, app = client
        payload = _sample_trace_batch()
        payload["events"][0]["future_packet_field"] = "would otherwise vanish"
        resp = c.post("/ingest/trace-batch", json=payload)
        assert resp.status_code == 422
        assert app.state.trace_batch_store.tail(1) == []

    def test_rejects_invalid_ip(self, client):
        c, _ = client
        payload = _sample_trace_batch()
        payload["events"][0]["src_ip"] = "not-an-ip"
        resp = c.post("/ingest/trace-batch", json=payload)
        assert resp.status_code == 422


class TestIngestGuardEvent:
    def test_accepts_valid_batch(self, client):
        c, app = client
        resp = c.post("/ingest/guard-event", json=_sample_guard_batch())
        assert resp.status_code == 202, resp.text
        assert resp.json()["accepted"] is True
        assert resp.json()["id"] == "g-1"
        assert resp.json()["derived_status"] == "complete"

        stored = app.state.guard_event_store.tail(1)[0]
        assert stored["batch_id"] == "g-1"
        kinds = [e["kind"] for e in stored["events"]]
        assert kinds == ["fim", "network"]

    def test_rejects_unknown_kind(self, client):
        c, _ = client
        payload = _sample_guard_batch()
        payload["events"][0]["kind"] = "wormhole"
        resp = c.post("/ingest/guard-event", json=payload)
        assert resp.status_code == 422

    def test_rejects_unknown_nested_guard_field(self, client):
        c, app = client
        payload = _sample_guard_batch()
        payload["events"][0]["future_guard_field"] = "would otherwise vanish"
        resp = c.post("/ingest/guard-event", json=payload)
        assert resp.status_code == 422
        assert app.state.guard_event_store.tail(1) == []

    def test_rejects_unknown_action(self, client):
        c, _ = client
        payload = _sample_guard_batch()
        payload["events"][0]["action_taken"] = "explode"
        resp = c.post("/ingest/guard-event", json=payload)
        assert resp.status_code == 422


class TestApiToken:
    @pytest.fixture
    def authed_client(self, tmp_path: Path):
        app = create_app(
            data_dir=tmp_path,
            api_token="secret-token",
            metrics_token="metrics-token",
        )
        with TestClient(app) as test_client:
            yield test_client

    def test_health_stays_public(self, authed_client):
        assert authed_client.get("/health").status_code == 200

    def test_readiness_requires_internal_token(self, authed_client):
        assert authed_client.get("/ready").status_code == 401
        assert (
            authed_client.get(
                "/ready",
                headers={"Authorization": "Bearer secret-token"},
            ).status_code
            == 200
        )

    def test_metrics_requires_distinct_read_only_token(self, authed_client):
        assert authed_client.get("/metrics").status_code == 401
        assert (
            authed_client.get(
                "/metrics",
                headers={"Authorization": "Bearer secret-token"},
            ).status_code
            == 401
        )
        assert (
            authed_client.get(
                "/metrics",
                headers={"Authorization": "Bearer metrics-token"},
            ).status_code
            == 200
        )

    def test_equal_internal_and_metrics_tokens_fail_closed(self, tmp_path: Path):
        with pytest.raises(RuntimeError, match="ANALYZER_METRICS_TOKEN must be distinct"):
            create_app(
                data_dir=tmp_path,
                api_token="shared",
                metrics_token="shared",
            )

    def test_ingest_rejects_missing_token(self, authed_client):
        resp = authed_client.post("/ingest/asset-report", json=_sample_asset_report())
        assert resp.status_code == 401

    def test_ingest_accepts_valid_token(self, authed_client):
        resp = authed_client.post(
            "/ingest/asset-report",
            json=_sample_asset_report(),
            headers={"Authorization": "Bearer secret-token"},
        )
        assert resp.status_code == 202

    def test_reports_reject_invalid_token(self, authed_client):
        resp = authed_client.get(
            "/reports/asset-reports",
            headers={"Authorization": "Bearer wrong"},
        )
        assert resp.status_code == 401


class TestInternalToken:
    def test_environment_token_protects_ingest_and_reports(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("ANALYZER_INTERNAL_TOKEN", "form-to-analyzer")
        app = create_app(data_dir=tmp_path)
        with TestClient(app) as client:
            assert client.get("/health").status_code == 200
            assert client.get("/reports/asset-reports").status_code == 401
            headers = {"Authorization": "Bearer form-to-analyzer"}
            assert (
                client.post(
                    "/ingest/asset-report", json=_sample_asset_report(), headers=headers
                ).status_code
                == 202
            )
            assert client.get("/reports/asset-reports", headers=headers).status_code == 200

    def test_legacy_external_tokens_are_not_analyzer_credentials(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("ANALYZER_INTERNAL_TOKEN", "internal")
        monkeypatch.setenv("ANALYZER_API_TOKEN", "legacy-admin")
        monkeypatch.setenv("ANALYZER_INGEST_TOKEN", "legacy-agent")
        app = create_app(data_dir=tmp_path)
        with TestClient(app) as client:
            for token in ("legacy-admin", "legacy-agent"):
                response = client.get(
                    "/reports/asset-reports",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code == 401


class TestTraceBatchCorrelation:
    def test_threat_intel_hit_creates_alert(self, client):
        c, app = client
        payload = _sample_trace_batch()
        payload["events"][0]["threat_intel"] = [
            {
                "indicator": "93.184.216.34",
                "indicator_type": "ip",
                "category": "c2",
                "severity": "high",
                "source": "builtin-demo",
                "description": "Known C2 node",
            }
        ]
        resp = c.post("/ingest/trace-batch", json=payload)
        assert resp.status_code == 202, resp.text

        alerts = app.state.alert_store.tail(10)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "high"
        assert alerts[0]["related_trace_ids"] == ["f-1"]

    def test_no_threat_intel_creates_no_alert(self, client):
        c, app = client
        resp = c.post("/ingest/trace-batch", json=_sample_trace_batch())
        assert resp.status_code == 202
        assert app.state.alert_store.tail(1) == []

    def test_cross_source_alert_when_collector_id_differs_from_asset(self, client):
        # C3 end-to-end: a real deployment where the collector observation point
        # ('collector-edge-1') is NOT the scanned asset ('asset-web-9'). The flow
        # endpoint IP (10.0.0.1) belongs to the asset, which has a critical vuln.
        # The ingest pipeline must resolve IP->asset and raise a cross-source
        # alert — the old host_id-as-asset join would have silently missed it.
        c, app = client

        report = _sample_asset_report()
        report["report_id"] = "r-web-9"
        report["host"]["host_id"] = "asset-web-9"
        report["host"]["ip_addrs"] = ["10.0.0.1"]
        report["vulnerabilities"] = [
            {
                "vuln_id": "CVE-2024-7777",
                "severity": "critical",
                "cvss_score": 9.8,
                "affected_asset_id": "pkg-1",
                "source": "osv",
            }
        ]
        # Persist a DetectionResult for the asset directly (critical vuln posture).
        from analyzer.schemas import DetectionResult, Vulnerability

        app.state.asset_report_store.append(AssetReport.model_validate(report))
        app.state.vulnerability_store.append(
            DetectionResult(
                report_id="r-web-9",
                host_id="asset-web-9",
                collected_at=NOW,
                ecosystem="Ubuntu:22.04",
                vulnerabilities=[
                    Vulnerability(
                        vuln_id="CVE-2024-7777",
                        severity="critical",
                        cvss_score=9.8,
                        affected_asset_id="pkg-1",
                        source="osv",
                    )
                ],
            )
        )

        batch = _sample_trace_batch()
        batch["collector_id"] = "collector-edge-1"
        batch["events"][0]["host_id"] = "collector-edge-1"  # observation point != asset
        batch["events"][0]["src_ip"] = "10.0.0.1"  # the asset's IP
        batch["events"][0]["threat_intel"] = [
            {
                "indicator": "93.184.216.34",
                "indicator_type": "ip",
                "category": "c2",
                "severity": "high",
                "source": "builtin-demo",
            }
        ]
        assert c.post("/ingest/trace-batch", json=batch).status_code == 202

        alerts = app.state.alert_store.tail(10)
        ioc = [a for a in alerts if a["alert_id"].startswith("alert-ioc-")]
        cross = [a for a in alerts if a["alert_id"].startswith("alert-cross-")]
        # IOC alert references the asset, not the collector.
        assert ioc[0]["related_asset_ids"] == ["asset-web-9"]
        # Cross-source alert fired despite collector id != asset id.
        assert len(cross) == 1
        assert cross[0]["severity"] == "critical"
        assert cross[0]["related_vuln_ids"] == ["CVE-2024-7777"]

    def test_alerts_endpoint_returns_generated_alerts(self, client):
        c, _ = client
        payload = _sample_trace_batch()
        payload["events"][0]["threat_intel"] = [
            {
                "indicator": "example.com",
                "indicator_type": "domain",
                "category": "phishing",
                "severity": "medium",
                "source": "builtin-demo",
            }
        ]
        c.post("/ingest/trace-batch", json=payload)

        resp = c.get("/reports/alerts")
        assert resp.status_code == 200
        alerts = resp.json()
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "medium"


class TestGetAlert:
    def test_get_alert_by_id(self, client):
        c, app = client
        payload = _sample_trace_batch()
        payload["events"][0]["threat_intel"] = [
            {
                "indicator": "example.com",
                "indicator_type": "domain",
                "category": "phishing",
                "severity": "medium",
                "source": "builtin-demo",
            }
        ]
        c.post("/ingest/trace-batch", json=payload)
        alert_id = app.state.alert_store.tail(1)[0]["alert_id"]
        resp = c.get(f"/reports/alerts/{alert_id}")
        assert resp.status_code == 200
        assert resp.json()["alert_id"] == alert_id

    def test_get_missing_alert_returns_404(self, client):
        c, _ = client
        assert c.get("/reports/alerts/does-not-exist").status_code == 404


class TestSqliteBackend:
    def test_ingest_and_read_with_sqlite(self, tmp_path: Path):
        app = create_app(data_dir=tmp_path, storage_backend="sqlite")
        with TestClient(app) as c:
            assert c.post("/ingest/asset-report", json=_sample_asset_report()).status_code == 202
            listed = c.get("/reports/asset-reports")
            assert listed.status_code == 200
            assert listed.json()[0]["report_id"] == "r-001"
        assert (tmp_path / "analyzer.db").exists()


class TestControlPlaneBoundary:
    @pytest.mark.parametrize(
        "method,path",
        [
            ("get", "/targets"),
            ("post", "/targets"),
            ("get", "/scans"),
            ("post", "/scans"),
            ("get", "/credentials"),
            ("post", "/targets/target-1/guard/stop"),
        ],
    )
    def test_control_plane_routes_are_not_mounted(self, client, method: str, path: str):
        test_client, _ = client
        response = test_client.post(path, json={}) if method == "post" else test_client.get(path)
        assert response.status_code == 404


class TestGuardEventsRead:
    def test_list_and_filter_by_host(self, client):
        c, _ = client
        assert c.post("/ingest/guard-event", json=_sample_guard_batch()).status_code == 202
        assert len(c.get("/reports/guard-events").json()) == 1
        assert len(c.get("/reports/guard-events", params={"host_id": "h-001"}).json()) == 1
        assert c.get("/reports/guard-events", params={"host_id": "other"}).json() == []

    def test_detections_missing_report_404(self, client):
        c, _ = client
        assert c.get("/reports/vulnerabilities/does-not-exist").status_code == 404
