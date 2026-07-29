"""Schema- and body-safe chunking for Form-owned telemetry forwarding.

Agent HTTP uploads arrive already chunked, but Form also assembles artifacts
from SSH/WinRM/local scans. Those artifacts can legitimately contain more rows
than one public envelope accepts. Keep the internal aggregate lossless, then
split it immediately before the private Analyzer hop.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any, TypeVar

from analyzer.schemas import FileTraceEvent, ProcessTraceEvent, TraceEvent
from pydantic import BaseModel, TypeAdapter

from .schemas import Asset, AssetReport, TraceBatch, Vulnerability

MAX_ENVELOPE_ITEMS = 4096
MAX_THREAT_MATCHES = 64
MAX_FORWARD_BODY_BYTES = 9 * 1024 * 1024
MAX_CORRELATION_ID_CHARS = 256
_HASH_LABEL = "~sha256:"
_LINEAGE_SUFFIX_RESERVE = 40

_Event = TypeVar("_Event", TraceEvent, FileTraceEvent, ProcessTraceEvent)
_ASSET = TypeAdapter(Asset)
_VULNERABILITY = TypeAdapter(Vulnerability)


def bounded_correlation_id(value: str) -> str:
    """Mirror Agent's UTF-8-safe prefix + full-SHA256 identifier policy."""
    if len(value) <= MAX_CORRELATION_ID_CHARS:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    prefix_chars = MAX_CORRELATION_ID_CHARS - len(_HASH_LABEL) - len(digest)
    return f"{value[:prefix_chars]}{_HASH_LABEL}{digest}"


def _child_id(original: str, kind: str, index: int, total: int) -> str:
    return bounded_correlation_id(f"{original}::{kind}-{index}-of-{total}")


def _lineage_root(original: str) -> str:
    """Reserve a stable suffix budget so long sibling IDs remain parseable."""
    if len(original) <= MAX_CORRELATION_ID_CHARS - _LINEAGE_SUFFIX_RESERVE:
        return original
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()
    prefix_chars = (
        MAX_CORRELATION_ID_CHARS - _LINEAGE_SUFFIX_RESERVE - len(_HASH_LABEL) - len(digest)
    )
    return f"{original[:prefix_chars]}{_HASH_LABEL}{digest}"


def _lineage_child(root: str, kind: str, index: int, total: int) -> str:
    value = f"{root}::{kind}-{index}-of-{total}"
    if len(value) > MAX_CORRELATION_ID_CHARS:
        raise RuntimeError("internal lineage identifier budget exceeded")
    return value


def _encoded_size(model: BaseModel) -> int:
    return len(model.model_dump_json().encode("utf-8"))


def _item_size(model: BaseModel) -> int:
    return len(model.model_dump_json().encode("utf-8"))


def split_asset_report(
    report: AssetReport,
    *,
    max_bytes: int = MAX_FORWARD_BODY_BYTES,
) -> list[AssetReport]:
    """Split an aggregate host report without dropping assets or findings."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    sizing = report.model_copy(
        update={
            "report_id": "x" * MAX_CORRELATION_ID_CHARS,
            "assets": [],
            "vulnerabilities": [],
        }
    )
    empty_bytes = _encoded_size(sizing)
    if empty_bytes > max_bytes:
        raise ValueError(f"empty AssetReport is {empty_bytes} bytes (limit {max_bytes})")

    packed: list[tuple[list[Any], list[Any]]] = []
    assets: list[Any] = []
    vulnerabilities: list[Any] = []
    current_bytes = empty_bytes

    def flush() -> None:
        nonlocal assets, vulnerabilities, current_bytes
        if assets or vulnerabilities:
            packed.append((assets, vulnerabilities))
            assets = []
            vulnerabilities = []
            current_bytes = empty_bytes

    def add(items: Iterable[BaseModel], *, vulnerability: bool) -> None:
        nonlocal current_bytes
        for item in items:
            target = vulnerabilities if vulnerability else assets
            item_bytes = _item_size(item)
            separator = int(bool(target))
            exceeds_count = len(target) >= MAX_ENVELOPE_ITEMS
            exceeds_bytes = current_bytes + separator + item_bytes > max_bytes
            if exceeds_count or exceeds_bytes:
                flush()
                target = vulnerabilities if vulnerability else assets
                separator = 0
            if current_bytes + separator + item_bytes > max_bytes:
                raise ValueError(
                    f"one AssetReport item needs at least {empty_bytes + item_bytes} bytes "
                    f"(limit {max_bytes})"
                )
            target.append(item)
            current_bytes += separator + item_bytes

    add(report.assets, vulnerability=False)
    add(report.vulnerabilities, vulnerability=True)
    flush()
    if not packed:
        packed.append(([], []))

    chunks: list[AssetReport] = []
    total = len(packed)
    lineage_root = _lineage_root(report.report_id) if total > 1 else report.report_id
    for index, (chunk_assets, chunk_vulnerabilities) in enumerate(packed, start=1):
        report_id = (
            lineage_root if index == 1 else _lineage_child(lineage_root, "chunk", index, total)
        )
        detector_runs = None
        if report.detector_runs is not None:
            source_by_detector = {
                "defender": {"microsoft-defender", "microsoft-defender-event"},
                "malware": {"kcatta-malware", "clamav"},
                "posture": {"posture"},
                "secret": {"secret"},
                "osv": set(),
                "debian_tracker": set(),
            }
            detector_runs = [
                run.model_copy(
                    update={
                        "finding_count": sum(
                            finding.source in source_by_detector[run.detector.value]
                            for finding in chunk_vulnerabilities
                        )
                    }
                )
                for run in report.detector_runs
            ]
        chunk = AssetReport.model_validate(
            report.model_copy(
                update={
                    "report_id": report_id,
                    "assets": chunk_assets,
                    "vulnerabilities": chunk_vulnerabilities,
                    "detector_runs": detector_runs,
                }
            ).model_dump(mode="python")
        )
        if _encoded_size(chunk) > max_bytes:
            raise RuntimeError("internal AssetReport chunking invariant failed")
        chunks.append(chunk)
    return chunks


def parse_unbounded_asset_report(text: str) -> AssetReport:
    """Validate a durable host artifact while deferring top-level list chunking."""
    raw = json.loads(text)
    if not isinstance(raw, dict):
        raise ValueError("AssetReport artifact must be a JSON object")
    header = dict(raw)
    raw_assets = header.pop("assets", [])
    raw_vulnerabilities = header.pop("vulnerabilities", [])
    if not isinstance(raw_assets, list) or not isinstance(raw_vulnerabilities, list):
        raise ValueError("AssetReport asset streams must be JSON arrays")
    validated_header = AssetReport.model_validate({**header, "assets": [], "vulnerabilities": []})
    return validated_header.model_copy(
        update={
            "assets": [_ASSET.validate_python(item) for item in raw_assets],
            "vulnerabilities": [
                _VULNERABILITY.validate_python(item) for item in raw_vulnerabilities
            ],
        }
    )


def _expand_threat_matches(
    raw_event: Any,
    model: type[_Event],
) -> list[_Event]:
    if not isinstance(raw_event, dict):
        raise ValueError("trace event must be a JSON object")
    matches = raw_event.get("threat_intel", [])
    if not isinstance(matches, list):
        raise ValueError("trace event threat_intel must be a JSON array")
    total = max(1, (len(matches) + MAX_THREAT_MATCHES - 1) // MAX_THREAT_MATCHES)
    expanded: list[_Event] = []
    for index in range(total):
        child = dict(raw_event)
        child["threat_intel"] = matches[
            index * MAX_THREAT_MATCHES : (index + 1) * MAX_THREAT_MATCHES
        ]
        if total > 1:
            original = str(child.get("trace_id", ""))
            child["trace_id"] = _child_id(original, "matches", index + 1, total)
        expanded.append(model.model_validate(child))
    return expanded


def parse_unbounded_trace_batch(text: str) -> TraceBatch:
    """Validate a trace artifact while allowing its top-level streams to be chunked later."""
    raw = json.loads(text)
    if not isinstance(raw, dict):
        raise ValueError("TraceBatch artifact must be a JSON object")
    header = dict(raw)
    raw_events = header.pop("events", [])
    raw_file_events = header.pop("file_events", [])
    raw_process_events = header.pop("process_events", [])
    if not all(
        isinstance(stream, list) for stream in (raw_events, raw_file_events, raw_process_events)
    ):
        raise ValueError("TraceBatch event streams must be JSON arrays")
    validated_header = TraceBatch.model_validate(
        {**header, "events": [], "file_events": [], "process_events": []}
    )
    events = [
        event for raw_event in raw_events for event in _expand_threat_matches(raw_event, TraceEvent)
    ]
    file_events = [
        event
        for raw_event in raw_file_events
        for event in _expand_threat_matches(raw_event, FileTraceEvent)
    ]
    process_events = [
        event
        for raw_event in raw_process_events
        for event in _expand_threat_matches(raw_event, ProcessTraceEvent)
    ]
    # Items and header are individually validated. The deliberately unbounded
    # aggregate is never exposed on a public route; split_trace_batch validates
    # each child before forwarding it.
    return validated_header.model_copy(
        update={
            "events": events,
            "file_events": file_events,
            "process_events": process_events,
        }
    )


def split_trace_batch(
    batch: TraceBatch,
    *,
    max_bytes: int = MAX_FORWARD_BODY_BYTES,
) -> list[TraceBatch]:
    """Split all trace streams under their count and serialized-byte budgets."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    sizing = batch.model_copy(
        update={
            "batch_id": "x" * MAX_CORRELATION_ID_CHARS,
            "events": [],
            "file_events": [],
            "process_events": [],
        }
    )
    empty_bytes = _encoded_size(sizing)
    if empty_bytes > max_bytes:
        raise ValueError(f"empty TraceBatch is {empty_bytes} bytes (limit {max_bytes})")

    packed: list[tuple[list[Any], list[Any], list[Any]]] = []
    events: list[Any] = []
    file_events: list[Any] = []
    process_events: list[Any] = []
    current_bytes = empty_bytes

    def flush() -> None:
        nonlocal events, file_events, process_events, current_bytes
        if events or file_events or process_events:
            packed.append((events, file_events, process_events))
            events, file_events, process_events = [], [], []
            current_bytes = empty_bytes

    def add(items: Iterable[BaseModel], stream: str) -> None:
        nonlocal current_bytes
        for item in items:
            target = {
                "events": events,
                "file_events": file_events,
                "process_events": process_events,
            }[stream]
            item_bytes = _item_size(item)
            separator = int(bool(target))
            if (
                len(target) >= MAX_ENVELOPE_ITEMS
                or current_bytes + separator + item_bytes > max_bytes
            ):
                flush()
                target = {
                    "events": events,
                    "file_events": file_events,
                    "process_events": process_events,
                }[stream]
                separator = 0
            if current_bytes + separator + item_bytes > max_bytes:
                raise ValueError(
                    f"one TraceBatch event needs at least {empty_bytes + item_bytes} bytes "
                    f"(limit {max_bytes})"
                )
            target.append(item)
            current_bytes += separator + item_bytes

    add(batch.events, "events")
    add(batch.file_events, "file_events")
    add(batch.process_events, "process_events")
    flush()
    if not packed:
        packed.append(([], [], []))

    chunks: list[TraceBatch] = []
    total = len(packed)
    lineage_root = _lineage_root(batch.batch_id) if total > 1 else batch.batch_id
    for index, (chunk_events, chunk_files, chunk_processes) in enumerate(packed, start=1):
        batch_id = (
            lineage_root if index == 1 else _lineage_child(lineage_root, "chunk", index, total)
        )
        chunk = TraceBatch.model_validate(
            batch.model_copy(
                update={
                    "batch_id": batch_id,
                    "events": chunk_events,
                    "file_events": chunk_files,
                    "process_events": chunk_processes,
                }
            ).model_dump(mode="python")
        )
        if _encoded_size(chunk) > max_bytes:
            raise RuntimeError("internal TraceBatch chunking invariant failed")
        chunks.append(chunk)
    return chunks
