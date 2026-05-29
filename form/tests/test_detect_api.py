"""Integration tests for the /detect endpoint.

Loads a fixture OSV store into a TestClient app and posts AssetReports,
asserting matched findings, the no-ecosystem error, and the pinned-ecosystem
override.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from form.api import create_app

NOW = datetime(2026, 5, 29, tzinfo=UTC)

OSV_OPENSSL = {
    "id": "DSA-TEST-openssl",
    "aliases": ["CVE-2099-0001"],
    "database_specific": {"severity": "High"},
    "references": [{"type": "ADVISORY", "url": "https://example.test/dsa"}],
    "affected": [
        {
            "package": {"ecosystem": "Debian:12", "name": "openssl"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.2-1"}]}
            ],
        }
    ],
}

CLAMAV_FINDING = {
    "vuln_id": "Eicar-Test-Signature",
    "severity": "critical",
    "cvss_score": None,
    "affected_asset_id": "h-1",
    "source": "clamav",
    "evidence": "infected file: /tmp/eicar.com",
    "references": [],
}


def _report(os_string: str, openssl_version: str, vulnerabilities: list | None = None) -> dict:
    return {
        "report_id": "r-1",
        "collected_at": NOW.isoformat(),
        "scanner_version": "0.1.0",
        "host": {"host_id": "h-1", "hostname": "n", "os": os_string},
        "assets": [
            {
                "kind": "package",
                "asset_id": "pkg-openssl",
                "name": "openssl",
                "version": openssl_version,
            }
        ],
        "vulnerabilities": vulnerabilities or [],
    }


@pytest.fixture
def osv_dir(tmp_path: Path) -> Path:
    db = tmp_path / "osv" / "Debian"
    db.mkdir(parents=True)
    (db / "DSA-TEST-openssl.json").write_text(json.dumps(OSV_OPENSSL), encoding="utf-8")
    return tmp_path / "osv"


@pytest.fixture
def client(tmp_path: Path, osv_dir: Path):
    app = create_app(data_dir=tmp_path / "data", osv_dir=osv_dir)
    with TestClient(app) as test_client:
        yield test_client


def test_detects_vulnerable_package(client):
    resp = client.post(
        "/detect/asset-report",
        json=_report("Debian GNU/Linux 12 (bookworm)", "3.0.2-0"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ecosystem"] == "Debian:12"
    assert len(body["vulnerabilities"]) == 1
    assert body["vulnerabilities"][0]["vuln_id"] == "CVE-2099-0001"
    assert body["vulnerabilities"][0]["severity"] == "high"
    assert body["vulnerabilities"][0]["source"] == "osv"


def test_fixed_package_yields_no_findings(client):
    resp = client.post(
        "/detect/asset-report",
        json=_report("Debian GNU/Linux 12 (bookworm)", "3.0.2-1"),
    )
    assert resp.status_code == 200
    assert resp.json()["vulnerabilities"] == []


def test_underivable_ecosystem_is_422(client):
    resp = client.post(
        "/detect/asset-report",
        json=_report("Kali GNU/Linux Rolling", "3.0.2-0"),
    )
    assert resp.status_code == 422
    assert "ecosystem" in resp.json()["detail"]


def test_clamav_only_without_ecosystem(client):
    resp = client.post(
        "/detect/asset-report",
        json=_report("Kali GNU/Linux Rolling", "3.0.2-0", [CLAMAV_FINDING]),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ecosystem"] == ""
    assert len(body["vulnerabilities"]) == 1
    assert body["vulnerabilities"][0]["source"] == "clamav"


def test_merges_osv_and_clamav(client):
    resp = client.post(
        "/detect/asset-report",
        json=_report("Debian GNU/Linux 12 (bookworm)", "3.0.2-0", [CLAMAV_FINDING]),
    )
    assert resp.status_code == 200, resp.text
    sources = [v["source"] for v in resp.json()["vulnerabilities"]]
    assert sources == ["osv", "clamav"]


def test_pinned_ecosystem_override(tmp_path: Path, osv_dir: Path):
    app = create_app(data_dir=tmp_path / "data", osv_dir=osv_dir, osv_ecosystem="Debian:12")
    with TestClient(app) as client:
        resp = client.post(
            "/detect/asset-report",
            json=_report("Kali GNU/Linux Rolling", "3.0.2-0"),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ecosystem"] == "Debian:12"
        assert len(body["vulnerabilities"]) == 1


class TestAutoDetectOnIngest:
    def test_ingest_persists_findings(self, tmp_path: Path, osv_dir: Path):
        data_dir = tmp_path / "data"
        app = create_app(data_dir=data_dir, osv_dir=osv_dir)
        with TestClient(app) as client:
            ack = client.post(
                "/ingest/asset-report",
                json=_report("Debian GNU/Linux 12", "3.0.2-0"),
            )
            assert ack.status_code == 202

            lines = (data_dir / "vulnerabilities.jsonl").read_text().splitlines()
            assert len(lines) == 1
            stored = json.loads(lines[0])
            assert stored["report_id"] == "r-1"
            assert stored["ecosystem"] == "Debian:12"
            assert stored["vulnerabilities"][0]["vuln_id"] == "CVE-2099-0001"

            listed = client.get("/reports/vulnerabilities")
            assert listed.status_code == 200
            assert listed.json()[0]["vulnerabilities"][0]["vuln_id"] == "CVE-2099-0001"

    def test_ingest_clamav_without_osv_store(self, tmp_path: Path):
        data_dir = tmp_path / "data"
        app = create_app(data_dir=data_dir, osv_dir=tmp_path / "empty")
        with TestClient(app) as client:
            assert (
                client.post(
                    "/ingest/asset-report",
                    json=_report("Debian GNU/Linux 12", "3.0.2-0", [CLAMAV_FINDING]),
                ).status_code
                == 202
            )
            lines = (data_dir / "vulnerabilities.jsonl").read_text().splitlines()
            assert len(lines) == 1
            stored = json.loads(lines[0])
            assert stored["vulnerabilities"][0]["source"] == "clamav"

    def test_ingest_merges_osv_and_clamav(self, tmp_path: Path, osv_dir: Path):
        data_dir = tmp_path / "data"
        app = create_app(data_dir=data_dir, osv_dir=osv_dir)
        with TestClient(app) as client:
            client.post(
                "/ingest/asset-report",
                json=_report("Debian GNU/Linux 12", "3.0.2-0", [CLAMAV_FINDING]),
            )
            stored = json.loads(
                (data_dir / "vulnerabilities.jsonl").read_text().splitlines()[0]
            )
            sources = [v["source"] for v in stored["vulnerabilities"]]
            assert sources == ["osv", "clamav"]

    def test_ingest_without_osv_store_skips_detection(self, tmp_path: Path):
        data_dir = tmp_path / "data"
        app = create_app(data_dir=data_dir, osv_dir=tmp_path / "empty")
        with TestClient(app) as client:
            assert (
                client.post(
                    "/ingest/asset-report",
                    json=_report("Debian GNU/Linux 12", "3.0.2-0"),
                ).status_code
                == 202
            )
            assert not (data_dir / "vulnerabilities.jsonl").exists()

    def test_ingest_unknown_ecosystem_skips_detection(self, tmp_path: Path, osv_dir: Path):
        data_dir = tmp_path / "data"
        app = create_app(data_dir=data_dir, osv_dir=osv_dir)
        with TestClient(app) as client:
            assert (
                client.post(
                    "/ingest/asset-report",
                    json=_report("Kali GNU/Linux Rolling", "3.0.2-0"),
                ).status_code
                == 202
            )
            assert not (data_dir / "vulnerabilities.jsonl").exists()

    def test_read_vulnerabilities_empty(self, tmp_path: Path, osv_dir: Path):
        app = create_app(data_dir=tmp_path / "data", osv_dir=osv_dir)
        with TestClient(app) as client:
            resp = client.get("/reports/vulnerabilities")
            assert resp.status_code == 200
            assert resp.json() == []
