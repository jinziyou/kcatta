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

from ..schemas import Asset, AssetReport, HostInfo, Vulnerability
from ._util import read_artifact_text, validate_artifact_set

_ASSET_FILES = ("packages.json", "services.json", "accounts.json", "credentials.json")
_MALWARE_JSON = "malware.json"
_ASSET_LIST = TypeAdapter(list[Asset])
_VULN_LIST = TypeAdapter(list[Vulnerability])


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
    """Merge malware hits from ``malware.json``, rebinding ``affected_asset_id`` to the host."""
    path = output_dir / _MALWARE_JSON
    if not path.is_file():
        return
    text = read_artifact_text(path)
    try:
        vulns = _VULN_LIST.validate_json(text)
    except Exception:  # noqa: BLE001 - a malformed malware.json must not break assembly
        return
    for vuln in vulns:
        vuln.affected_asset_id = report.host.host_id
    report.vulnerabilities = vulns


def finalize_asset_report(output_dir: Path) -> AssetReport:
    """:func:`assemble_asset_report` plus :func:`attach_malware` when present."""
    artifacts = [
        path
        for name in ("host.json", *_ASSET_FILES, _MALWARE_JSON)
        if (path := output_dir / name).is_file()
    ]
    validate_artifact_set(artifacts)
    report = assemble_asset_report(output_dir)
    attach_malware(report, output_dir)
    return report


def write_asset_report(output_dir: Path, report: AssetReport) -> Path:
    """Write ``asset_report.json`` next to the pulled per-asset files."""
    path = output_dir / "asset_report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path
