from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kcatta_form.deploy import defender
from kcatta_form.deploy.report import finalize_asset_report


def _write_host(directory: Path) -> None:
    (directory / "host.json").write_text(
        json.dumps(
            {
                "host_id": "windows-host",
                "hostname": "WIN-01",
                "os": "Windows 11",
                "ip_addrs": [],
                "mac_addrs": [],
            }
        ),
        encoding="utf-8",
    )
    (directory / "findings.json").write_text("[]", encoding="utf-8")
    (directory / "detector-runs.json").write_text("[]", encoding="utf-8")


def _snapshot() -> defender.DefenderSnapshot:
    now = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
    return defender.DefenderSnapshot(
        collected_at=now,
        enabled=True,
        requested_scan="quick",
        scan_status="complete",
        status=defender.DefenderStatus(
            product_version="4.18.26010.1",
            engine_version="1.1.26010.1",
            signature_version="1.455.1.0",
            signature_updated_at=now,
            signatures_out_of_date=False,
            running_mode="Normal",
            service_enabled=True,
            antivirus_enabled=True,
            real_time_protection=True,
            behavior_monitor=True,
            ioav_protection=True,
            tamper_protection=True,
            cloud_protection=True,
            last_quick_scan_at=now,
        ),
        threats=[
            defender.DefenderThreat(
                threat_id="2147519003",
                name="Virus:DOS/EICAR_Test_File",
                severity_id=4,
                active=False,
            )
        ],
        detections=[
            defender.DefenderDetection(
                threat_id="2147519003",
                detection_id="det-1",
                initial_detection_at=now,
                action_success=True,
                resources=["file:_C:\\Temp\\eicar.com"],
            )
        ],
        events=[
            defender.DefenderEvent(
                event_id=1121,
                record_id=42,
                created_at=now,
                level="Warning",
                message="An attack surface reduction rule blocked an action.",
            )
        ],
    )


def test_defender_snapshot_becomes_asset_findings_and_coverage(tmp_path: Path) -> None:
    _write_host(tmp_path)
    (tmp_path / defender.DEFENDER_ARTIFACT).write_text(
        _snapshot().model_dump_json(), encoding="utf-8"
    )

    report = finalize_asset_report(tmp_path)

    product = next(asset for asset in report.assets if asset.kind == "security_product")
    assert product.asset_id == defender.DEFENDER_ASSET_ID
    assert product.status == "active"
    assert product.real_time_protection is True
    assert product.signature_version == "1.455.1.0"
    assert {item.source for item in report.vulnerabilities} == {
        defender.DEFENDER_SOURCE,
        defender.DEFENDER_EVENT_SOURCE,
    }
    assert all(
        item.affected_asset_id == defender.DEFENDER_ASSET_ID
        for item in report.vulnerabilities
    )
    assert report.detector_runs is not None
    run = next(item for item in report.detector_runs if item.detector == "defender")
    assert run.status == "complete"
    assert run.finding_count == len(report.vulnerabilities)


def test_defender_unavailable_is_explicit_failed_not_false_clean(tmp_path: Path) -> None:
    _write_host(tmp_path)
    snapshot = defender.failed_snapshot(
        enabled=True,
        requested_scan="quick",
        reason="defender_collection_failed",
    )
    (tmp_path / defender.DEFENDER_ARTIFACT).write_text(
        snapshot.model_dump_json(), encoding="utf-8"
    )

    report = finalize_asset_report(tmp_path)

    product = next(asset for asset in report.assets if asset.kind == "security_product")
    assert product.status == "unavailable"
    assert report.vulnerabilities == []
    assert report.detector_runs is not None
    run = next(item for item in report.detector_runs if item.detector == "defender")
    assert run.status == "failed"
    assert run.reason == "defender_unavailable"


def test_status_only_collection_does_not_claim_detector_execution(tmp_path: Path) -> None:
    _write_host(tmp_path)
    snapshot = _snapshot().model_copy(
        update={
            "enabled": False,
            "requested_scan": None,
            "scan_status": "not_requested",
            "threats": [],
            "detections": [],
            "events": [],
        }
    )
    (tmp_path / defender.DEFENDER_ARTIFACT).write_text(
        snapshot.model_dump_json(), encoding="utf-8"
    )

    report = finalize_asset_report(tmp_path)

    assert any(asset.kind == "security_product" for asset in report.assets)
    assert report.vulnerabilities == []
    assert report.detector_runs == []


def test_bounded_source_overflow_is_partial_and_combined_findings_are_not_silently_cut() -> None:
    snapshot = _snapshot().model_copy(
        update={
            "errors": ["defender_operational_log_truncated"],
            "threats": [
                defender.DefenderThreat(threat_id=f"threat-{index}", severity_id=3)
                for index in range(defender.DEFENDER_MAX_RECORDS)
            ],
            "detections": [
                defender.DefenderDetection(threat_id=f"detection-{index}")
                for index in range(defender.DEFENDER_MAX_RECORDS)
            ],
            "events": [
                defender.DefenderEvent(
                    event_id=1121,
                    record_id=index,
                    created_at=datetime(2026, 7, 16, tzinfo=UTC),
                )
                for index in range(defender.DEFENDER_MAX_RECORDS)
            ],
        }
    )

    findings = defender.defender_findings(snapshot)
    run = defender.defender_detector_run(snapshot, finding_count=len(findings))

    assert len(findings) == defender.DEFENDER_MAX_RECORDS * 3
    assert run is not None
    assert run.status == "partial"
    assert run.reason == "defender_telemetry_partial"


def test_powershell_adapter_uses_bounded_local_defender_cmdlets() -> None:
    script = defender._powershell_snapshot("C:\\Temp\\defender.json", "quick")

    assert "Start-MpScan -ScanType QuickScan" in script
    assert "Get-MpComputerStatus" in script
    assert "Get-MpThreatDetection" in script
    assert "Microsoft-Windows-Windows Defender/Operational" in script
    assert f"Select-Object -First {defender.DEFENDER_MAX_RECORDS}" in script
    assert f"Select-Object -First {defender.DEFENDER_QUERY_RECORDS}" in script
    assert "defender_operational_log_truncated" in script
    assert "ConvertTo-Json -Depth 6 -Compress" in script


def test_full_and_none_modes_do_not_fall_back_to_kcatta_signatures() -> None:
    full = defender._powershell_snapshot("C:\\Temp\\defender.json", "full")
    history_only = defender._powershell_snapshot("C:\\Temp\\defender.json", "none")

    assert "Start-MpScan -ScanType FullScan" in full
    assert "Start-MpScan" not in history_only
    assert "kcatta-malware" not in full
