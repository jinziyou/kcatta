"""Analyzer /ready degraded OSV semantics and /metrics exposition."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from analyzer import metrics as metrics_mod
from analyzer.api.app import create_app
from analyzer.detect import DEFAULT_OSV_ECOSYSTEMS, sync_debian_tracker


def _record(record_id: str, ecosystem: str) -> dict:
    return {
        "id": record_id,
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": "sample"},
                "versions": ["1.0"],
            }
        ],
    }


def _tracker_dir(tmp_path: Path) -> Path:
    source = tmp_path / "tracker.json"
    source.write_text(
        json.dumps(
            {
                "sample": {
                    "CVE-2099-0001": {
                        "releases": {
                            "trixie": {
                                "status": "open",
                                "repositories": {"trixie": "1.0"},
                                "urgency": "high",
                            }
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    directory = tmp_path / "tracker"
    sync_debian_tracker(directory, json_file=source)
    return directory


def test_ready_is_degraded_but_200_when_osv_empty(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "true")
    monkeypatch.delenv("ANALYZER_INTERNAL_TOKEN", raising=False)
    app = create_app(data_dir=tmp_path, osv_dir=tmp_path / "empty-osv")
    with TestClient(app) as client:
        response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["osv"] == "empty"
    assert body["osv_record_count"] == 0
    assert body["debian_tracker"] == "empty"
    assert body["debian_tracker_record_count"] == 0
    assert body["debian_tracker_source_package_count"] == 0


def test_metrics_exposes_osv_gauge(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "true")
    monkeypatch.delenv("ANALYZER_INTERNAL_TOKEN", raising=False)
    metrics_mod.reset()
    app = create_app(data_dir=tmp_path, osv_dir=tmp_path / "empty-osv")
    with TestClient(app) as client:
        response = client.get("/metrics")
    assert response.status_code == 200
    assert "kcatta_osv_records" in response.text
    assert "kcatta_osv_sync_complete" in response.text
    assert "kcatta_debian_tracker_records" in response.text
    assert "text/plain" in response.headers["content-type"]


def test_ready_marks_nonempty_uncommitted_osv_store_partial(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "true")
    osv = tmp_path / "osv"
    osv.mkdir()
    (osv / "record.json").write_text(json.dumps(_record("CVE-TEST", "Debian:12")), encoding="utf-8")

    app = create_app(data_dir=tmp_path / "data", osv_dir=osv)
    with TestClient(app) as client:
        partial = client.get("/ready").json()
    assert partial["status"] == "degraded"
    assert partial["osv"] == "partial"
    assert partial["osv_complete"] is False


def test_ready_requires_complete_marker_for_full_osv_coverage(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "true")
    osv = tmp_path / "osv"
    osv.mkdir()
    for index, ecosystem in enumerate(DEFAULT_OSV_ECOSYSTEMS):
        (osv / f"record-{index}.json").write_text(
            json.dumps(_record(f"CVE-TEST-{index}", ecosystem)),
            encoding="utf-8",
        )
    (osv / ".complete").write_text(
        json.dumps(
            {
                "ecosystems": list(DEFAULT_OSV_ECOSYSTEMS),
                "record_counts": {ecosystem: 1 for ecosystem in DEFAULT_OSV_ECOSYSTEMS},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    app = create_app(
        data_dir=tmp_path / "data",
        osv_dir=osv,
        debian_tracker_dir=_tracker_dir(tmp_path),
    )
    with TestClient(app) as client:
        ready = client.get("/ready").json()
    assert ready["status"] == "ready"
    assert ready["osv"] == "ready"
    assert ready["osv_complete"] is True
    assert ready["debian_tracker"] == "ready"


def test_ready_marks_stale_tracker_degraded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "true")
    tracker = _tracker_dir(tmp_path)
    old_sync = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    with sqlite3.connect(tracker / "index.sqlite3") as connection:
        connection.execute(
            "UPDATE metadata SET value = ? WHERE key = 'synced_at'",
            (old_sync,),
        )
        connection.commit()

    app = create_app(
        data_dir=tmp_path / "data",
        osv_dir=tmp_path / "empty-osv",
        debian_tracker_dir=tracker,
        debian_tracker_max_age_hours=1,
    )
    with TestClient(app) as client:
        ready = client.get("/ready").json()

    assert ready["status"] == "degraded"
    assert ready["debian_tracker"] == "stale"
    assert ready["debian_tracker_age_seconds"] > ready["debian_tracker_max_age_seconds"]
    assert ready["debian_tracker_synced_at"] == old_sync


def test_ready_discloses_missing_default_ecosystems(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "true")
    osv = tmp_path / "osv"
    osv.mkdir()
    (osv / "record.json").write_text(json.dumps(_record("CVE-TEST", "Debian:12")), encoding="utf-8")
    (osv / ".complete").write_text(
        json.dumps({"ecosystems": ["Debian"], "record_counts": {"Debian": 1}}) + "\n",
        encoding="utf-8",
    )

    app = create_app(data_dir=tmp_path / "data", osv_dir=osv)
    with TestClient(app) as client:
        ready = client.get("/ready").json()

    assert ready["status"] == "degraded"
    assert ready["osv"] == "partial"
    assert ready["osv_complete"] is False
    assert "Ubuntu" in ready["osv_missing_ecosystems"]


def test_ready_rejects_manifest_when_one_ecosystem_record_count_mismatches(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "true")
    osv = tmp_path / "osv"
    osv.mkdir()
    (osv / "record.json").write_text(json.dumps(_record("CVE-TEST", "Debian:12")), encoding="utf-8")
    (osv / ".complete").write_text(
        json.dumps({"ecosystems": ["Debian"], "record_counts": {"Debian": 2}}) + "\n",
        encoding="utf-8",
    )

    app = create_app(
        data_dir=tmp_path / "data",
        osv_dir=osv,
        osv_ecosystem="Debian:12",
    )
    with TestClient(app) as client:
        ready = client.get("/ready").json()

    assert ready["status"] == "degraded"
    assert ready["osv_complete"] is False
    assert ready["osv_mismatched_ecosystems"] == ["Debian"]
