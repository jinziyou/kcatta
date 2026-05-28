"""Integration tests for the form HTTP API.

These exercise the full request -> Pydantic validation -> persistence
path with FastAPI's TestClient, redirecting writes to a pytest
``tmp_path`` so each test gets a clean filesystem.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from form.api import create_app

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


def _sample_flow_batch() -> dict:
    return {
        "batch_id": "b-1",
        "collected_at": NOW.isoformat(),
        "collector_id": "col-1",
        "collector_version": "0.1.0",
        "flows": [
            {
                "flow_id": "f-1",
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


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(data_dir=tmp_path)
    with TestClient(app) as test_client:
        yield test_client, tmp_path


class TestHealth:
    def test_health_endpoint(self, client):
        c, _ = client
        resp = c.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestIngestAssetReport:
    def test_accepts_valid_report(self, client):
        c, tmp = client
        resp = c.post("/ingest/asset-report", json=_sample_asset_report())
        assert resp.status_code == 202, resp.text
        assert resp.json() == {"accepted": True, "id": "r-001"}

        lines = (tmp / "asset-reports.jsonl").read_text().splitlines()
        assert len(lines) == 1
        stored = json.loads(lines[0])
        assert stored["report_id"] == "r-001"
        assert stored["assets"][0]["kind"] == "package"

    def test_rejects_unknown_field(self, client):
        c, tmp = client
        payload = _sample_asset_report()
        payload["surprise"] = "boom"
        resp = c.post("/ingest/asset-report", json=payload)
        assert resp.status_code == 422
        assert not (tmp / "asset-reports.jsonl").exists()

    def test_rejects_unknown_asset_kind(self, client):
        c, _ = client
        payload = _sample_asset_report()
        payload["assets"] = [{"kind": "alien", "asset_id": "a"}]
        resp = c.post("/ingest/asset-report", json=payload)
        assert resp.status_code == 422

    def test_appends_multiple_reports(self, client):
        c, tmp = client
        first = _sample_asset_report()
        second = _sample_asset_report()
        second["report_id"] = "r-002"

        assert c.post("/ingest/asset-report", json=first).status_code == 202
        assert c.post("/ingest/asset-report", json=second).status_code == 202

        lines = (tmp / "asset-reports.jsonl").read_text().splitlines()
        assert [json.loads(line)["report_id"] for line in lines] == ["r-001", "r-002"]


class TestReadAssetReports:
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


class TestReadFlowBatches:
    def test_empty_when_no_uploads(self, client):
        c, _ = client
        resp = c.get("/reports/flow-batches")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_uploaded_batches_newest_first(self, client):
        c, _ = client
        first = _sample_flow_batch()
        second = _sample_flow_batch()
        second["batch_id"] = "b-2"
        c.post("/ingest/flow-batch", json=first)
        c.post("/ingest/flow-batch", json=second)

        resp = c.get("/reports/flow-batches")
        ids = [b["batch_id"] for b in resp.json()]
        assert ids == ["b-2", "b-1"]


class TestCors:
    def test_allows_localhost_origin(self, tmp_path):
        app = create_app(data_dir=tmp_path)
        with TestClient(app) as c:
            resp = c.options(
                "/health",
                headers={
                    "Origin": "http://localhost:3000",
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert resp.status_code == 200
            assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"


class TestIngestFlowBatch:
    def test_accepts_valid_batch(self, client):
        c, tmp = client
        resp = c.post("/ingest/flow-batch", json=_sample_flow_batch())
        assert resp.status_code == 202, resp.text
        assert resp.json() == {"accepted": True, "id": "b-1"}

        lines = (tmp / "flow-batches.jsonl").read_text().splitlines()
        assert len(lines) == 1
        stored = json.loads(lines[0])
        assert stored["batch_id"] == "b-1"
        assert stored["flows"][0]["proto"] == "tcp"

    def test_rejects_invalid_proto(self, client):
        c, _ = client
        payload = _sample_flow_batch()
        payload["flows"][0]["proto"] = "xyz"
        resp = c.post("/ingest/flow-batch", json=payload)
        assert resp.status_code == 422

    def test_rejects_invalid_ip(self, client):
        c, _ = client
        payload = _sample_flow_batch()
        payload["flows"][0]["src_ip"] = "not-an-ip"
        resp = c.post("/ingest/flow-batch", json=payload)
        assert resp.status_code == 422
