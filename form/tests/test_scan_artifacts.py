"""Durable scan-artifact handoff survives retries without lossy revalidation."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from analyzer.schemas import AssetReport, HostInfo, Package, TraceBatch, TraceEvent
from analyzer.storage import StorageCapacityError

from kcatta_form.scan_artifacts import ScanArtifactStore
from kcatta_form.schemas import ScanCapability, ScanResult

NOW = datetime(2026, 7, 10, tzinfo=UTC)


def _report(count: int, *, padding: int = 0) -> AssetReport:
    return AssetReport.model_construct(
        report_id="report-1",
        collected_at=NOW,
        scanner_version="test",
        host=HostInfo(host_id="host-1", hostname="node", os="Linux"),
        assets=[
            Package(
                asset_id=f"pkg-{index}",
                name=f"pkg-{index}-{'x' * padding}",
                version="1",
            )
            for index in range(count)
        ],
        vulnerabilities=[],
    )


def _trace(index: int) -> TraceEvent:
    return TraceEvent(
        trace_id=f"trace-{index}",
        host_id="host-1",
        start_ts=NOW,
        end_ts=NOW,
        proto="tcp",
        src_ip="10.0.0.1",
        dst_ip="192.0.2.1",
        bytes_sent=index,
        bytes_recv=0,
    )


def test_unbounded_asset_report_round_trips_and_deletes(tmp_path: Path) -> None:
    store = ScanArtifactStore(tmp_path / "spool")
    report = _report(4_097)

    written = store.save("scan-assets", "asset-report", report)
    loaded = store.load("scan-assets")

    assert loaded is not None
    metadata, restored = loaded
    assert metadata.sha256 == written.sha256
    assert isinstance(restored, AssetReport)
    assert isinstance(restored.host, HostInfo)
    assert len(restored.assets) == 4_097
    assert [asset.asset_id for asset in restored.assets] == [
        asset.asset_id for asset in report.assets
    ]
    store.delete("scan-assets")
    assert store.load("scan-assets") is None


def test_unbounded_trace_batch_round_trips(tmp_path: Path) -> None:
    store = ScanArtifactStore(tmp_path / "spool")
    batch = TraceBatch.model_construct(
        batch_id="batch-1",
        collected_at=NOW,
        collector_id="collector-1",
        collector_version="test",
        events=[_trace(index) for index in range(4_097)],
        file_events=[],
        process_events=[],
    )

    store.save("scan-trace", "trace-batch", batch)
    loaded = store.load("scan-trace")

    assert loaded is not None
    _, restored = loaded
    assert isinstance(restored, TraceBatch)
    assert isinstance(restored.events[0], TraceEvent)
    assert len(restored.events) == 4_097


def test_scan_result_round_trips_for_resident_guard(tmp_path: Path) -> None:
    store = ScanArtifactStore(tmp_path / "spool")
    result = ScanResult(kind=ScanCapability.GUARD, pid="42", detail="started")

    store.save("scan-guard", "scan-result", result)
    loaded = store.load("scan-guard")

    assert loaded is not None
    assert loaded[1] == result


def test_item_and_total_quotas_fail_without_replacing_existing_artifact(tmp_path: Path) -> None:
    # Derive exact envelope sizes so adding optional contract fields cannot turn
    # the aggregate-quota assertion into an item-quota assertion.
    sizing = ScanArtifactStore(
        tmp_path / "sizing",
        max_artifact_bytes=100_000,
        max_total_bytes=100_000,
    )
    first_size = sizing.save("scan-one", "asset-report", _report(1)).size
    second_size = sizing.save(
        "scan-two", "asset-report", _report(1, padding=1_400)
    ).size
    store = ScanArtifactStore(
        tmp_path / "spool",
        max_artifact_bytes=second_size,
        max_total_bytes=first_size + second_size - 1,
    )
    original = _report(1)
    store.save("scan-one", "asset-report", original)

    with pytest.raises(StorageCapacityError, match="spool limit"):
        store.save("scan-too-large", "asset-report", _report(1, padding=3_000))

    before = store.load("scan-one")
    with pytest.raises(StorageCapacityError, match="would exceed"):
        store.save("scan-two", "asset-report", _report(1, padding=1_400))
    after = store.load("scan-one")
    assert before is not None and after is not None
    assert before[0].sha256 == after[0].sha256


@pytest.mark.skipif(os.name != "posix", reason="symlink ownership boundary is POSIX-specific")
def test_symlinked_job_artifact_is_rejected(tmp_path: Path) -> None:
    store = ScanArtifactStore(tmp_path / "spool")
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (store.root / "scan-link.json").symlink_to(outside)

    with pytest.raises(RuntimeError, match="not a regular file"):
        store.load("scan-link")
    with pytest.raises(RuntimeError, match="refusing to unlink"):
        store.delete("scan-link")


def test_reconcile_removes_orphans_and_crash_temporary_files(tmp_path: Path) -> None:
    store = ScanArtifactStore(tmp_path / "spool")
    store.save("scan-keep", "asset-report", _report(1))
    store.save("scan-orphan", "asset-report", _report(1))
    temporary = store.root / ".scan-crash.deadbeef.tmp"
    temporary.write_bytes(b"partial")

    removed = store.reconcile(lambda job_id: job_id == "scan-keep")

    assert removed == 2
    assert store.load("scan-keep") is not None
    assert store.load("scan-orphan") is None
    assert not temporary.exists()


def test_artifact_identity_type_and_checksum_are_verified(tmp_path: Path) -> None:
    store = ScanArtifactStore(tmp_path / "spool")
    with pytest.raises(TypeError, match="requires AssetReport"):
        store.save(
            "scan-wrong-type",
            "asset-report",
            ScanResult(kind=ScanCapability.GUARD, pid="42"),
        )

    store.save("scan-tampered", "asset-report", _report(1))
    path = store.root / "scan-tampered.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["payload"]["host"]["hostname"] = "attacker-modified"
    path.write_text(json.dumps(envelope, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(ValueError, match="checksum mismatch"):
        store.load("scan-tampered")
