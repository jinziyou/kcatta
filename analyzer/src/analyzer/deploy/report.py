"""Assemble an :class:`AssetReport` from per-asset JSON pulled off a target.

The JSON files written by ``agent-host -o DIR`` mirror analyzer's own Pydantic
contracts, so we validate them directly with :mod:`analyzer.schemas` rather than a
separate Rust-side mirror.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

from pydantic import TypeAdapter

from ..schemas import Asset, AssetReport, HostInfo, Vulnerability

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
    host = HostInfo.model_validate_json(host_path.read_text(encoding="utf-8"))

    assets: list[Asset] = []
    for fname in _ASSET_FILES:
        path = output_dir / fname
        if path.is_file():
            assets.extend(_ASSET_LIST.validate_json(path.read_text(encoding="utf-8")))

    return AssetReport(
        report_id=f"report-{uuid.uuid4()}",
        collected_at=datetime.now(UTC),
        scanner_version="analyzer-scan/0.1",
        host=host,
        assets=assets,
        vulnerabilities=[],
    )


def attach_malware(report: AssetReport, output_dir: Path) -> None:
    """Merge malware hits from ``malware.json``, rebinding ``affected_asset_id`` to the host."""
    path = output_dir / _MALWARE_JSON
    if not path.is_file():
        return
    try:
        vulns = _VULN_LIST.validate_json(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - a malformed malware.json must not break assembly
        return
    for vuln in vulns:
        vuln.affected_asset_id = report.host.host_id
    report.vulnerabilities = vulns


def finalize_asset_report(output_dir: Path) -> AssetReport:
    """:func:`assemble_asset_report` plus :func:`attach_malware` when present."""
    report = assemble_asset_report(output_dir)
    attach_malware(report, output_dir)
    return report


def write_asset_report(output_dir: Path, report: AssetReport) -> Path:
    """Write ``asset_report.json`` next to the pulled per-asset files."""
    path = output_dir / "asset_report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def upload_asset_report(report: AssetReport, form_base_url: str) -> None:
    """POST the report to analyzer's ``/ingest/asset-report`` (ANALYZER_API_TOKEN bearer)."""
    url = form_base_url.strip().rstrip("/") + "/ingest/asset-report"
    body = report.model_dump_json().encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    token = os.environ.get("ANALYZER_API_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"analyzer ingest failed ({exc.code}): {detail}") from exc
    if status != 202:
        raise RuntimeError(f"analyzer ingest returned unexpected status {status}")


def upload_flow_batch(flow_json: Path, analyzer_base_url: str) -> None:
    """POST a pulled `FlowBatch` JSON file to analyzer's ``/ingest/flow-batch``."""
    url = analyzer_base_url.strip().rstrip("/") + "/ingest/flow-batch"
    body = flow_json.read_bytes()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    token = os.environ.get("ANALYZER_API_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"analyzer flow ingest failed ({exc.code}): {detail}") from exc
    if status != 202:
        raise RuntimeError(f"analyzer flow ingest returned unexpected status {status}")
