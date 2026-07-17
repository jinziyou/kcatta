"""Debian Security Tracker indexing and conservative Kali matching tests."""

from __future__ import annotations

import asyncio
import io
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from analyzer import metrics as metrics_mod
from analyzer.api.app import _refresh_debian_tracker_once
from analyzer.detect import (
    DebianTrackerStore,
    detect_kali_packages,
    merge_kali_tracker_status,
    sync_debian_tracker,
)
from analyzer.detect.debian_tracker import iter_tracker_packages
from analyzer.detect.limits import FindingLimitState
from analyzer.schemas import AssetReport, DetectionStatus


def _issue(
    status: str,
    version: str,
    *,
    fixed_version: str | None = None,
    urgency: str = "high",
) -> dict:
    release = {
        "status": status,
        "repositories": {"trixie": version},
        "urgency": urgency,
    }
    if fixed_version is not None:
        release["fixed_version"] = fixed_version
    return {"scope": "local", "releases": {"trixie": release}}


def _feed(*, include_undetermined: bool = False) -> dict:
    issues = {
        "CVE-2099-0001": _issue("open", "3.0.0-1"),
        "CVE-2099-0002": _issue("resolved", "3.0.0-1", fixed_version="2.9.0-1", urgency="low"),
        "CVE-2099-0003": _issue("resolved", "3.0.0-1", fixed_version="0", urgency="unimportant"),
    }
    if include_undetermined:
        issues["CVE-2099-0004"] = _issue("undetermined", "3.0.0-1")
    return {"openssl": issues}


def _write_index(tmp_path: Path, feed: dict | None = None) -> DebianTrackerStore:
    source = tmp_path / "tracker.json"
    source.write_text(json.dumps(feed or _feed()), encoding="utf-8")
    directory = tmp_path / "tracker"
    sync_debian_tracker(directory, json_file=source)
    return DebianTrackerStore.load(directory)


def _report(packages: list[dict]) -> AssetReport:
    return AssetReport.model_validate(
        {
            "report_id": "r-kali",
            "collected_at": datetime(2026, 7, 16, tzinfo=UTC).isoformat(),
            "scanner_version": "0.1.0",
            "host": {
                "host_id": "h-kali",
                "hostname": "kali",
                "os": "Kali GNU/Linux Rolling 2026.2",
            },
            "assets": packages,
            "vulnerabilities": [],
        }
    )


def _package(asset_id: str, source_version: str) -> dict:
    return {
        "kind": "package",
        "asset_id": asset_id,
        "name": "libssl3t64",
        "version": source_version,
        "source": "dpkg",
        "source_name": "openssl",
        "source_version": source_version,
        "ecosystem": "Kali:rolling",
    }


class _TinyReads(io.StringIO):
    def read(self, size: int = -1) -> str:
        return super().read(7 if size < 0 else min(size, 7))


def test_streaming_parser_handles_tokens_split_across_reads() -> None:
    feed = _feed()
    assert list(iter_tracker_packages(_TinyReads(json.dumps(feed)))) == [
        ("openssl", feed["openssl"])
    ]


def test_sync_builds_exact_version_lookup(tmp_path: Path) -> None:
    store = _write_index(tmp_path)

    assert store.available is True
    assert store.source_package_count == 1
    assert store.record_count == 3
    assert store.synced_at is not None
    assert store.age_seconds() is not None and store.age_seconds() < 60
    rows = store.lookup("openssl", "3.0.0-1")
    assert [row.advisory_id for row in rows] == [
        "CVE-2099-0001",
        "CVE-2099-0002",
        "CVE-2099-0003",
    ]
    assert store.lookup("openssl", "3.0.0-1+kali1") == []


def test_old_index_remains_available_but_is_marked_stale(tmp_path: Path) -> None:
    store = _write_index(tmp_path)
    store.close()
    old_sync = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    with sqlite3.connect(tmp_path / "tracker" / "index.sqlite3") as connection:
        connection.execute(
            "UPDATE metadata SET value = ? WHERE key = 'synced_at'",
            (old_sync,),
        )
        connection.commit()

    stale = DebianTrackerStore.load(tmp_path / "tracker", max_age_seconds=3600)

    assert stale.available is True
    assert stale.stale is True
    assert stale.lookup("openssl", "3.0.0-1")


def test_failed_sync_preserves_previous_atomic_index(tmp_path: Path) -> None:
    store = _write_index(tmp_path)
    store.close()
    bad = tmp_path / "bad.json"
    bad.write_text('{"openssl": ', encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        sync_debian_tracker(tmp_path / "tracker", json_file=bad)

    recovered = DebianTrackerStore.load(tmp_path / "tracker")
    assert recovered.record_count == 3
    assert recovered.lookup("openssl", "3.0.0-1")


def test_background_refresh_hot_swaps_a_valid_index(tmp_path: Path) -> None:
    source = tmp_path / "refresh.json"
    source.write_text(json.dumps(_feed()), encoding="utf-8")
    old = DebianTrackerStore(max_age_seconds=3600)
    application = SimpleNamespace(
        state=SimpleNamespace(debian_tracker_store=old),
    )
    metrics_mod.reset()

    refreshed = asyncio.run(
        _refresh_debian_tracker_once(
            application,
            tmp_path / "tracker",
            3600,
            syncer=lambda directory: sync_debian_tracker(directory, json_file=source),
        )
    )

    assert refreshed is True
    assert application.state.debian_tracker_store.available is True
    assert application.state.debian_tracker_store.stale is False
    counters, _ = metrics_mod.snapshot()
    assert counters["kcatta_debian_tracker_refresh_success_total"] == 1


def test_failed_background_refresh_keeps_previous_index(tmp_path: Path) -> None:
    old = _write_index(tmp_path)
    application = SimpleNamespace(
        state=SimpleNamespace(debian_tracker_store=old),
    )
    metrics_mod.reset()

    def fail(_directory: str | Path) -> tuple[int, int]:
        raise OSError("offline")

    refreshed = asyncio.run(
        _refresh_debian_tracker_once(
            application,
            tmp_path / "tracker",
            3600,
            syncer=fail,
        )
    )

    assert refreshed is False
    assert application.state.debian_tracker_store is old
    assert old.lookup("openssl", "3.0.0-1")
    counters, _ = metrics_mod.snapshot()
    assert counters["kcatta_debian_tracker_refresh_failures_total"] == 1


def test_kali_detection_requires_exact_debian_source_version(tmp_path: Path) -> None:
    store = _write_index(tmp_path)
    report = _report(
        [
            _package("pkg-exact", "3.0.0-1"),
            _package("pkg-kali-fork", "3.0.0-1+kali1"),
        ]
    )

    result = detect_kali_packages(report, store)

    assert result.candidate_count == 2
    assert result.verified_count == 1
    assert result.unverified_count == 1
    assert result.osv_report.assets == []
    assert [(item.vuln_id, item.affected_asset_id) for item in result.findings] == [
        ("CVE-2099-0001", "pkg-exact")
    ]
    assert result.findings[0].source == "debian-security-tracker"
    assert result.findings[0].severity == "high"


def test_source_level_cve_is_not_repeated_for_each_binary_package(tmp_path: Path) -> None:
    store = _write_index(tmp_path)
    first = _package("pkg-libssl", "3.0.0-1")
    second = _package("pkg-openssl", "3.0.0-1")
    second["name"] = "openssl"

    result = detect_kali_packages(_report([first, second]), store)

    assert result.candidate_count == 2
    assert result.verified_count == 2
    assert result.unverified_count == 0
    assert len(result.findings) == 1
    assert result.findings[0].affected_asset_id == "pkg-libssl"
    assert "libssl3t64 3.0.0-1" in result.findings[0].evidence
    assert "openssl 3.0.0-1" in result.findings[0].evidence


def test_undetermined_tracker_status_is_explicitly_partial(tmp_path: Path) -> None:
    store = _write_index(tmp_path, _feed(include_undetermined=True))
    result = detect_kali_packages(_report([_package("pkg-exact", "3.0.0-1")]), store)
    state = FindingLimitState()

    status, reason = merge_kali_tracker_status(
        DetectionStatus.DISABLED,
        "osv_store_empty",
        result,
        store,
        state,
        osv_candidate_count=0,
    )

    assert result.incomplete_count == 1
    assert status == DetectionStatus.PARTIAL
    assert reason == "debian_tracker_advisory_undetermined"


def test_tracker_only_run_can_be_complete_when_osv_is_empty(tmp_path: Path) -> None:
    store = _write_index(tmp_path)
    result = detect_kali_packages(_report([_package("pkg-exact", "3.0.0-1")]), store)

    status, reason = merge_kali_tracker_status(
        DetectionStatus.DISABLED,
        "osv_store_empty",
        result,
        store,
        FindingLimitState(),
        osv_candidate_count=0,
    )

    assert status == DetectionStatus.COMPLETE
    assert reason is None


def test_stale_tracker_forces_partial_detection_status(tmp_path: Path) -> None:
    store = _write_index(tmp_path)
    store.max_age_seconds = 0
    result = detect_kali_packages(_report([_package("pkg-exact", "3.0.0-1")]), store)

    status, reason = merge_kali_tracker_status(
        DetectionStatus.COMPLETE,
        None,
        result,
        store,
        FindingLimitState(),
        osv_candidate_count=0,
    )

    assert store.stale is True
    assert status == DetectionStatus.PARTIAL
    assert reason == "debian_tracker_stale"
