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

from analyzer.api import create_app
from analyzer.api import ingest as ingest_api
from analyzer.detect import sync_debian_tracker
from analyzer.schemas import DetectionResult

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

POSTURE_FINDING = {
    "vuln_id": "POSTURE-SSHD-PERMIT-ROOT-LOGIN-YES",
    "severity": "high",
    "cvss_score": None,
    "affected_asset_id": "h-1",
    "source": "posture",
    "evidence": "/etc/ssh/sshd_config:12: `PermitRootLogin yes`",
    "references": [],
}

SECRET_FINDING = {
    "vuln_id": "SECRET-PRIVATE-KEY-PEM::etc/ssl/host.key#1",
    "severity": "critical",
    "cvss_score": None,
    "affected_asset_id": "h-1",
    "source": "secret",
    # Redacted by construction on the agent: no plaintext key bytes.
    "evidence": "type=private-key kind=RSA encrypted=false path=etc/ssl/host.key line=1",
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
    (tmp_path / "osv" / ".complete").write_text(
        json.dumps({"ecosystems": ["Debian"], "record_counts": {"Debian": 1}}) + "\n",
        encoding="utf-8",
    )
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
    body = resp.json()
    assert body["vulnerabilities"] == []
    assert body["detection_status"] == "complete"
    assert body["scanned_package_count"] == 1
    coverage = {(row["detector"], row["ecosystem"]): row for row in body["coverage"]}
    assert coverage[("osv", "Debian:12")]["status"] == "complete"
    assert coverage[("osv", "Debian:12")]["scanned_count"] == 1
    assert coverage[("defender", None)]["status"] == "unknown"
    assert coverage[("malware", None)]["status"] == "unknown"
    assert coverage[("posture", None)]["status"] == "unknown"
    assert coverage[("secret", None)]["status"] == "unknown"


def test_detector_matrix_distinguishes_completed_zero_from_disabled(client):
    payload = _report("Debian GNU/Linux 12 (bookworm)", "3.0.2-1")
    payload["detector_runs"] = [{"detector": "posture", "status": "complete", "finding_count": 0}]

    body = client.post("/detect/asset-report", json=payload).json()
    coverage = {row["detector"]: row for row in body["coverage"]}

    assert coverage["posture"]["status"] == "complete"
    assert coverage["posture"]["finding_count"] == 0
    assert coverage["defender"]["status"] == "disabled"
    assert coverage["malware"]["status"] == "disabled"
    assert coverage["secret"]["status"] == "disabled"


def test_detector_matrix_marks_declared_count_mismatch_partial(client):
    payload = _report(
        "Debian GNU/Linux 12 (bookworm)",
        "3.0.2-1",
        [POSTURE_FINDING],
    )
    payload["detector_runs"] = [{"detector": "posture", "status": "complete", "finding_count": 0}]

    body = client.post("/detect/asset-report", json=payload).json()
    posture = next(row for row in body["coverage"] if row["detector"] == "posture")

    assert posture["status"] == "partial"
    assert posture["finding_count"] == 1
    assert posture["reason"] == "detector_finding_count_mismatch"


def test_detector_matrix_groups_ecosystems_without_exceeding_contract_limit(client):
    payload = _report("Debian GNU/Linux 12 (bookworm)", "3.0.2-1")
    payload["assets"] = [
        {
            "kind": "package",
            "asset_id": f"pkg-{index}",
            "name": f"package-{index}",
            "version": "1.0",
            "ecosystem": f"Custom:{index}",
        }
        for index in range(254)
    ]
    payload["detector_runs"] = []

    response = client.post("/detect/asset-report", json=payload)

    assert response.status_code == 200, response.text
    rows = response.json()["coverage"]
    assert len(rows) == 256
    grouped = next(row for row in rows if row.get("reason") == "coverage_matrix_grouped")
    assert grouped["skipped_count"] == 3


def test_detector_matrix_surfaces_defender_findings_and_declared_run(client):
    payload = _report(
        "Debian GNU/Linux 12 (bookworm)",
        "3.0.2-1",
        [
            {
                "vuln_id": "DEFENDER-det-1",
                "severity": "critical",
                "affected_asset_id": "security-product-microsoft-defender",
                "source": "microsoft-defender",
            }
        ],
    )
    payload["detector_runs"] = [
        {"detector": "defender", "status": "complete", "finding_count": 1}
    ]

    body = client.post("/detect/asset-report", json=payload).json()
    defender = next(row for row in body["coverage"] if row["detector"] == "defender")

    assert defender["status"] == "complete"
    assert defender["finding_count"] == 1
    assert any(item["source"] == "microsoft-defender" for item in body["vulnerabilities"])


def test_detect_rejects_unknown_nested_fields_instead_of_discarding_them(client):
    payload = _report("Debian GNU/Linux 12 (bookworm)", "3.0.2-1")
    payload["assets"][0]["future_package_field"] = "would otherwise vanish"

    resp = client.post("/detect/asset-report", json=payload)

    assert resp.status_code == 422


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


def test_kali_exact_source_package_uses_debian_tracker_without_osv(tmp_path: Path):
    feed = {
        "openssl": {
            "CVE-2099-9001": {
                "scope": "local",
                "releases": {
                    "trixie": {
                        "status": "open",
                        "repositories": {"trixie": "3.0.0-1"},
                        "urgency": "high",
                    }
                },
            }
        }
    }
    source = tmp_path / "tracker.json"
    source.write_text(json.dumps(feed), encoding="utf-8")
    tracker_dir = tmp_path / "tracker"
    sync_debian_tracker(tracker_dir, json_file=source)
    app = create_app(
        data_dir=tmp_path / "data",
        osv_dir=tmp_path / "empty-osv",
        debian_tracker_dir=tracker_dir,
    )
    payload = _report("Kali GNU/Linux Rolling 2026.2", "3.0.0-1")
    payload["assets"][0].update(
        {
            "source": "dpkg",
            "source_name": "openssl",
            "source_version": "3.0.0-1",
            "ecosystem": "Kali:rolling",
        }
    )

    with TestClient(app) as tracker_client:
        response = tracker_client.post("/detect/asset-report", json=payload)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["detection_status"] == "complete"
    assert body["scanned_package_count"] == 1
    assert body["unresolved_package_count"] == 0
    assert body["vulnerabilities"][0]["vuln_id"] == "CVE-2099-9001"
    assert body["vulnerabilities"][0]["source"] == "debian-security-tracker"
    tracker_row = next(row for row in body["coverage"] if row["detector"] == "debian_tracker")
    assert tracker_row["status"] == "complete"
    assert tracker_row["scanned_count"] == 1


def test_merges_osv_and_clamav(client):
    resp = client.post(
        "/detect/asset-report",
        json=_report("Debian GNU/Linux 12 (bookworm)", "3.0.2-0", [CLAMAV_FINDING]),
    )
    assert resp.status_code == 200, resp.text
    sources = [v["source"] for v in resp.json()["vulnerabilities"]]
    assert sources == ["osv", "clamav"]


def test_posture_finding_surfaces_through_detect(client):
    # Agent-attached posture misconfig must surface end-to-end (not be dropped),
    # alongside the OSV CVE for the package.
    resp = client.post(
        "/detect/asset-report",
        json=_report("Debian GNU/Linux 12 (bookworm)", "3.0.2-0", [POSTURE_FINDING]),
    )
    assert resp.status_code == 200, resp.text
    vulns = resp.json()["vulnerabilities"]
    assert any(
        v["source"] == "posture" and v["vuln_id"] == "POSTURE-SSHD-PERMIT-ROOT-LOGIN-YES"
        for v in vulns
    )


def test_secret_finding_surfaces_through_detect(client):
    # Agent-attached secret-leak finding must surface end-to-end (whitelisted).
    resp = client.post(
        "/detect/asset-report",
        json=_report("Debian GNU/Linux 12 (bookworm)", "3.0.2-0", [SECRET_FINDING]),
    )
    assert resp.status_code == 200, resp.text
    vulns = resp.json()["vulnerabilities"]
    secret = next((v for v in vulns if v["source"] == "secret"), None)
    assert secret is not None and secret["vuln_id"].startswith("SECRET-PRIVATE-KEY-PEM")
    # The contract carries no plaintext secret field; evidence is redacted upstream.
    assert "private-key" in secret["evidence"]


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

            stored = app.state.vulnerability_store.tail(1)[0]
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
            stored = app.state.vulnerability_store.tail(1)[0]
            assert stored["vulnerabilities"][0]["source"] == "clamav"

    def test_ingest_merges_osv_and_clamav(self, tmp_path: Path, osv_dir: Path):
        data_dir = tmp_path / "data"
        app = create_app(data_dir=data_dir, osv_dir=osv_dir)
        with TestClient(app) as client:
            client.post(
                "/ingest/asset-report",
                json=_report("Debian GNU/Linux 12", "3.0.2-0", [CLAMAV_FINDING]),
            )
            stored = app.state.vulnerability_store.tail(1)[0]
            sources = [v["source"] for v in stored["vulnerabilities"]]
            assert sources == ["osv", "clamav"]

    def test_ingest_discloses_finding_truncation(self, tmp_path: Path, monkeypatch):
        app = create_app(data_dir=tmp_path / "data", osv_dir=tmp_path / "empty")

        def truncated_scanner(_report, *, limit_state):
            limit_state.mark("scanner_max_bytes")
            return []

        monkeypatch.setattr("analyzer.api.ingest.scanner_findings", truncated_scanner)
        payload = _report("Debian GNU/Linux 12", "3.0.2-0")
        payload["detector_runs"] = [
            {"detector": "posture", "status": "complete", "finding_count": 0}
        ]
        with TestClient(app) as client:
            ack = client.post(
                "/ingest/asset-report",
                json=payload,
            )

            assert ack.status_code == 202
            assert ack.json()["derived_truncated"] is True
            assert ack.json()["derived_reason"] == "osv_store_empty"
            stored = app.state.vulnerability_store.tail(1)[0]
            assert stored["truncated"] is True
            assert stored["truncation_reason"] == "scanner_max_bytes"
            matrix = {row["detector"]: row for row in stored["coverage"]}
            assert matrix["posture"]["status"] == "partial"
            assert matrix["posture"]["reason"] == "scanner_max_bytes"
            assert matrix["malware"]["status"] == "disabled"
            assert matrix["secret"]["status"] == "disabled"

    def test_ingest_marks_nonfatal_osv_record_failure_partial(
        self, tmp_path: Path, osv_dir: Path, monkeypatch
    ):
        (osv_dir / ".complete").write_text(
            json.dumps({"ecosystems": ["Debian"], "record_counts": {"Debian": 1}}) + "\n",
            encoding="utf-8",
        )
        app = create_app(data_dir=tmp_path / "data", osv_dir=osv_dir)

        def incomplete_detection(_report, _store, _ecosystem, *, limit_state):
            limit_state.mark_incomplete("osv_record_comparison_failed")
            return []

        monkeypatch.setattr("analyzer.api.ingest.detect_report", incomplete_detection)
        with TestClient(app) as client:
            ack = client.post(
                "/ingest/asset-report",
                json=_report("Debian GNU/Linux 12", "3.0.2-0"),
            )

            assert ack.status_code == 202
            assert ack.json()["derived_status"] == "partial"
            assert ack.json()["derived_reason"] == "osv_record_comparison_failed"
            stored = app.state.vulnerability_store.tail(1)[0]
            assert stored["detection_status"] == "partial"
            assert stored["status_reason"] == "osv_record_comparison_failed"
            assert stored["truncated"] is False

    def test_failed_derivation_is_retryable_without_duplicating_raw_report(
        self, tmp_path: Path, osv_dir: Path, monkeypatch
    ):
        app = create_app(data_dir=tmp_path / "data", osv_dir=osv_dir)
        original = ingest_api.detect_report

        def fail_detection(*_args, **_kwargs):
            raise RuntimeError("temporary detector failure")

        monkeypatch.setattr(ingest_api, "detect_report", fail_detection)
        payload = _report("Debian GNU/Linux 12", "3.0.2-1")
        # Current producers explicitly report that no Agent-side detectors ran.
        # Omitting this field is a legacy/unknown coverage signal and correctly
        # keeps the derived result partial even when OSV detection succeeds.
        payload["detector_runs"] = []
        with TestClient(app) as client:
            failed = client.post("/ingest/asset-report", json=payload)
            monkeypatch.setattr(ingest_api, "detect_report", original)
            retried = client.post("/ingest/asset-report", json=payload)

        assert failed.status_code == 503
        assert failed.json()["detail"]["derived_status"] == "failed"
        assert retried.status_code == 202
        assert retried.json()["derived_status"] == "complete"
        assert len(app.state.asset_report_store.tail(10)) == 1

    def test_ingest_without_osv_store_persists_disabled_status(self, tmp_path: Path):
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
            stored = app.state.vulnerability_store.tail(1)[0]
            assert stored["vulnerabilities"] == []
            assert stored["detection_status"] == "disabled"
            assert stored["status_reason"] == "osv_store_empty"

    def test_ingest_unknown_ecosystem_persists_partial_status(self, tmp_path: Path, osv_dir: Path):
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
            stored = app.state.vulnerability_store.tail(1)[0]
            assert stored["vulnerabilities"] == []
            assert stored["detection_status"] == "partial"
            assert stored["status_reason"] == "ecosystem_unresolved"
            assert stored["unresolved_package_count"] == 1

    def test_ingest_without_package_inventory_is_never_a_verified_clean_pass(
        self, tmp_path: Path, osv_dir: Path
    ):
        app = create_app(data_dir=tmp_path / "data", osv_dir=osv_dir)
        payload = _report("Debian GNU/Linux 12", "3.0.2-1")
        payload["assets"] = []
        with TestClient(app) as client:
            response = client.post("/ingest/asset-report", json=payload)

        assert response.status_code == 202
        stored = app.state.vulnerability_store.tail(1)[0]
        assert stored["detection_status"] == "partial"
        assert stored["status_reason"] == "no_package_inventory"
        assert stored["scanned_package_count"] == 0

    def test_ingest_marks_windows_packages_as_unsupported_osv_coverage(
        self, tmp_path: Path, osv_dir: Path
    ):
        app = create_app(data_dir=tmp_path / "data", osv_dir=osv_dir)
        payload = _report("Windows 11", "1.0")
        payload["assets"][0]["ecosystem"] = "Windows:11"
        with TestClient(app) as client:
            response = client.post("/ingest/asset-report", json=payload)

        assert response.status_code == 202
        stored = app.state.vulnerability_store.tail(1)[0]
        assert stored["detection_status"] == "partial"
        assert stored["status_reason"] == "osv_ecosystem_unsupported"
        assert stored["scanned_package_count"] == 0
        assert stored["uncovered_package_count"] == 1

    def test_read_vulnerabilities_empty(self, tmp_path: Path, osv_dir: Path):
        app = create_app(data_dir=tmp_path / "data", osv_dir=osv_dir)
        with TestClient(app) as client:
            resp = client.get("/reports/vulnerabilities")
            assert resp.status_code == 200
            assert resp.json() == []


def test_legacy_detection_without_coverage_fields_defaults_to_partial() -> None:
    legacy = DetectionResult.model_validate(
        {
            "report_id": "legacy-r",
            "host_id": "legacy-h",
            "collected_at": NOW.isoformat(),
            "ecosystem": "Debian:12",
            "vulnerabilities": [],
        }
    )

    assert legacy.detection_status.value == "partial"
    assert legacy.status_reason == "legacy_coverage_unknown"
