"""Assemble an :class:`AssetReport` from per-asset JSON pulled off a target for Form.

The JSON files written by ``agent-collect-host -o DIR`` mirror the shared Pydantic
contracts, so we validate them directly rather than using a
separate Rust-side mirror.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from pydantic import TypeAdapter

from ..schemas import Asset, AssetReport, DetectorRun, HostInfo, Vulnerability
from ._util import read_artifact_text, validate_artifact_set
from .defender import (
    DEFENDER_ARTIFACT,
    DEFENDER_ASSET_ID,
    defender_detector_run,
    defender_findings,
    failed_snapshot,
    load_defender_snapshot,
    security_product,
)

_ASSET_FILES = (
    "packages.json",
    "services.json",
    "ports.json",
    "accounts.json",
    "credentials.json",
    "containers.json",
    "images.json",
)
_FINDINGS_JSON = "findings.json"
_DETECTOR_RUNS_JSON = "detector-runs.json"
_MALWARE_JSON = "malware.json"
_SBOM_JSON = "sbom.cyclonedx.json"
_ASSET_LIST = TypeAdapter(list[Asset])
_VULN_LIST = TypeAdapter(list[Vulnerability])
_DETECTOR_RUN_LIST = TypeAdapter(list[DetectorRun])


def assemble_asset_report(output_dir: Path) -> AssetReport:
    """Build an AssetReport from ``host.json`` + per-asset files under ``output_dir``.

    ``host.json`` is required (use ``-t host`` or ``-t all``); the per-asset
    files are optional and merged into ``assets`` when present.
    """
    host_path = output_dir / "host.json"
    if not host_path.is_file():
        raise FileNotFoundError(
            f"host.json missing under {output_dir}; assembly requires -t host or all"
        )
    present = [host_path]
    present.extend(path for fname in _ASSET_FILES if (path := output_dir / fname).is_file())
    validate_artifact_set(present)
    host = HostInfo.model_validate_json(read_artifact_text(host_path))

    assets: list[Asset] = []
    for fname in _ASSET_FILES:
        path = output_dir / fname
        if path.is_file():
            assets.extend(_ASSET_LIST.validate_json(read_artifact_text(path)))

    # The private aggregate may exceed one public envelope's item cap. Every
    # nested item and the header have already been validated; AnalyzerClient
    # splits and re-validates schema-safe children before forwarding.
    return AssetReport.model_construct(
        report_id=f"report-{uuid.uuid4()}",
        collected_at=datetime.now(UTC),
        scanner_version="form-scan/0.1",
        host=host,
        assets=assets,
        vulnerabilities=[],
    )


def attach_malware(report: AssetReport, output_dir: Path) -> None:
    """Compatibility reader for pre-findings ``malware.json`` artifacts."""
    path = output_dir / _MALWARE_JSON
    if not path.is_file():
        return
    vulns = _VULN_LIST.validate_json(read_artifact_text(path))
    for vuln in vulns:
        vuln.affected_asset_id = report.host.host_id
    report.vulnerabilities = vulns


def attach_findings(report: AssetReport, output_dir: Path) -> None:
    """Attach the canonical posture/malware/secret finding stream.

    New agents always write ``findings.json`` (including ``[]`` for a clean
    scan).  ``malware.json`` is accepted only as a backward-compatible fallback
    so the same malware row is never attached twice.
    """
    path = output_dir / _FINDINGS_JSON
    if not path.is_file():
        attach_malware(report, output_dir)
        return
    vulns = _VULN_LIST.validate_json(read_artifact_text(path))
    for vuln in vulns:
        vuln.affected_asset_id = report.host.host_id
    report.vulnerabilities = vulns


def attach_detector_runs(report: AssetReport, output_dir: Path) -> None:
    """Attach explicit detector execution evidence, preserving legacy unknown."""

    path = output_dir / _DETECTOR_RUNS_JSON
    if not path.is_file():
        return
    report.detector_runs = _DETECTOR_RUN_LIST.validate_json(read_artifact_text(path))


def attach_defender(report: AssetReport, output_dir: Path) -> None:
    """Attach bounded local Defender health, findings, and execution evidence."""

    path = output_dir / DEFENDER_ARTIFACT
    if not path.is_file():
        return
    try:
        snapshot = load_defender_snapshot(path)
    except Exception:
        snapshot = failed_snapshot(
            enabled=True,
            requested_scan=None,
            reason="defender_artifact_invalid",
        )
    report.assets = [
        asset for asset in report.assets if getattr(asset, "asset_id", None) != DEFENDER_ASSET_ID
    ]
    report.assets.append(security_product(snapshot))
    findings = defender_findings(snapshot)
    report.vulnerabilities.extend(findings)
    run = defender_detector_run(snapshot, finding_count=len(findings))
    if run is not None:
        existing = report.detector_runs or []
        report.detector_runs = [item for item in existing if item.detector != run.detector]
        report.detector_runs.append(run)


def finalize_asset_report(output_dir: Path) -> AssetReport:
    """Assemble all wire assets and the canonical detector finding stream."""
    if (output_dir / _SBOM_JSON).is_file():
        raise ValueError(
            "CycloneDX SBOM is a standalone export and is not part of AssetReport; "
            "use scan_target=all to upload canonical package assets"
        )
    artifacts = [
        path
        for name in (
            "host.json",
            *_ASSET_FILES,
            _FINDINGS_JSON,
            _DETECTOR_RUNS_JSON,
            _MALWARE_JSON,
            DEFENDER_ARTIFACT,
        )
        if (path := output_dir / name).is_file()
    ]
    validate_artifact_set(artifacts)
    report = assemble_asset_report(output_dir)
    attach_findings(report, output_dir)
    attach_detector_runs(report, output_dir)
    attach_defender(report, output_dir)
    return report


def write_asset_report(output_dir: Path, report: AssetReport) -> Path:
    """Write ``asset_report.json`` next to the pulled per-asset files."""
    path = output_dir / "asset_report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path
