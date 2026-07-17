"""Lossless envelope chunking for Form-triggered host and trace scans."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import httpx
import pytest
from analyzer.schemas import (
    AssetReport,
    DetectorKind,
    DetectorRun,
    HostInfo,
    Package,
    Severity,
    TraceBatch,
    TraceEvent,
    Vulnerability,
)

from kcatta_form.analyzer_client import AnalyzerClient, AnalyzerUpstreamError
from kcatta_form.telemetry_chunks import (
    MAX_ENVELOPE_ITEMS,
    bounded_correlation_id,
    parse_unbounded_trace_batch,
    split_asset_report,
    split_trace_batch,
)

NOW = datetime(2026, 7, 10, tzinfo=UTC)


def _host() -> HostInfo:
    return HostInfo(host_id="host-1", hostname="node-1", os="Linux")


def _package(index: int, *, padding: int = 0) -> Package:
    return Package(
        asset_id=f"pkg-{index}",
        name=f"package-{index}-{'x' * padding}",
        version="1.0.0",
        source="test",
    )


def _trace(index: int, *, padding: int = 0) -> TraceEvent:
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
        tls_sni=f"example-{index}.invalid{'x' * padding}",
    )


def _unbounded_report(count: int) -> AssetReport:
    return AssetReport.model_construct(
        report_id="report-original",
        collected_at=NOW,
        scanner_version="test",
        host=_host(),
        assets=[_package(index) for index in range(count)],
        vulnerabilities=[],
    )


def test_asset_report_count_chunks_preserve_every_item_and_validate() -> None:
    assets = [_package(index) for index in range(MAX_ENVELOPE_ITEMS + 4)]
    vulnerabilities = [
        Vulnerability(
            vuln_id=f"CVE-2026-{index:04d}",
            severity=Severity.MEDIUM,
            affected_asset_id=f"pkg-{index}",
            source="test",
        )
        for index in range(MAX_ENVELOPE_ITEMS + 4)
    ]
    report = AssetReport.model_construct(
        report_id="report-original",
        collected_at=NOW,
        scanner_version="test",
        host=_host(),
        assets=assets,
        vulnerabilities=vulnerabilities,
    )

    chunks = split_asset_report(report)

    assert [item.asset_id for chunk in chunks for item in chunk.assets] == [
        item.asset_id for item in assets
    ]
    assert [item.vuln_id for chunk in chunks for item in chunk.vulnerabilities] == [
        item.vuln_id for item in vulnerabilities
    ]
    assert all(len(chunk.assets) <= MAX_ENVELOPE_ITEMS for chunk in chunks)
    assert all(len(chunk.vulnerabilities) <= MAX_ENVELOPE_ITEMS for chunk in chunks)
    assert chunks[0].report_id == report.report_id
    assert len({chunk.report_id for chunk in chunks}) == len(chunks)
    assert all(len(chunk.report_id) <= 256 for chunk in chunks)
    assert all(
        AssetReport.model_validate_json(chunk.model_dump_json()) == chunk for chunk in chunks
    )


def test_asset_report_byte_chunks_are_exactly_bounded() -> None:
    report = AssetReport(
        report_id="report-byte-limit",
        collected_at=NOW,
        scanner_version="test",
        host=_host(),
        assets=[_package(index, padding=1_000) for index in range(7)],
    )

    chunks = split_asset_report(report, max_bytes=2_500)

    assert len(chunks) > 1
    assert [item.asset_id for chunk in chunks for item in chunk.assets] == [
        item.asset_id for item in report.assets
    ]
    assert all(len(chunk.model_dump_json().encode()) <= 2_500 for chunk in chunks)


def test_asset_chunks_recount_detector_findings_per_child() -> None:
    findings = [
        Vulnerability(
            vuln_id=f"POSTURE-{index}",
            severity=Severity.HIGH,
            affected_asset_id="host-1",
            source="posture",
            evidence="x" * 900,
        )
        for index in range(3)
    ]
    report = AssetReport(
        report_id="report-detector-runs",
        collected_at=NOW,
        scanner_version="test",
        host=_host(),
        vulnerabilities=findings,
        detector_runs=[DetectorRun(detector=DetectorKind.POSTURE, finding_count=len(findings))],
    )

    chunks = split_asset_report(report, max_bytes=2_000)

    assert len(chunks) > 1
    assert sum(chunk.detector_runs[0].finding_count for chunk in chunks) == len(findings)  # type: ignore[index]
    assert all(
        chunk.detector_runs[0].finding_count == len(chunk.vulnerabilities)  # type: ignore[index]
        for chunk in chunks
    )


def test_asset_chunks_recount_defender_sources_per_child() -> None:
    findings = [
        Vulnerability(
            vuln_id=f"DEFENDER-{index}",
            severity=Severity.HIGH,
            affected_asset_id="security-product-microsoft-defender",
            source=("microsoft-defender" if index % 2 == 0 else "microsoft-defender-event"),
            evidence="x" * 900,
        )
        for index in range(3)
    ]
    report = AssetReport(
        report_id="report-defender-runs",
        collected_at=NOW,
        scanner_version="test",
        host=_host(),
        vulnerabilities=findings,
        detector_runs=[DetectorRun(detector=DetectorKind.DEFENDER, finding_count=len(findings))],
    )

    chunks = split_asset_report(report, max_bytes=2_000)

    assert len(chunks) > 1
    assert sum(chunk.detector_runs[0].finding_count for chunk in chunks) == len(findings)  # type: ignore[index]


def test_long_form_chunk_ids_preserve_one_parseable_lineage_root() -> None:
    report = _unbounded_report(MAX_ENVELOPE_ITEMS + 1).model_copy(
        update={"report_id": "节点" * 128}
    )

    chunks = split_asset_report(report)

    assert len(chunks) == 2
    root = chunks[0].report_id
    assert root != report.report_id
    assert chunks[1].report_id == f"{root}::chunk-2-of-2"
    assert len(chunks[1].report_id) <= 256


def test_unbounded_trace_parser_splits_nested_threat_matches_losslessly() -> None:
    threat_matches = [
        {
            "indicator": f"bad-{index}.invalid",
            "indicator_type": "domain",
            "category": "c2",
            "severity": "high",
            "source": "test-feed",
        }
        for index in range(130)
    ]
    raw = {
        "batch_id": "batch-original",
        "collected_at": "2026-07-10T00:00:00Z",
        "collector_id": "collector-1",
        "collector_version": "test",
        "events": [
            {
                "trace_id": "trace-original",
                "host_id": "host-1",
                "start_ts": "2026-07-10T00:00:00Z",
                "end_ts": "2026-07-10T00:00:01Z",
                "proto": "tcp",
                "src_ip": "10.0.0.1",
                "dst_ip": "192.0.2.1",
                "bytes_sent": 1,
                "bytes_recv": 2,
                "threat_intel": threat_matches,
            }
        ],
    }

    batch = parse_unbounded_trace_batch(json.dumps(raw))

    assert [len(event.threat_intel) for event in batch.events] == [64, 64, 2]
    assert [match.indicator for event in batch.events for match in event.threat_intel] == [
        match["indicator"] for match in threat_matches
    ]
    assert len({event.trace_id for event in batch.events}) == 3
    assert all(len(event.trace_id) <= 256 for event in batch.events)


def test_trace_count_and_byte_chunks_preserve_stream_order() -> None:
    events = [_trace(index) for index in range(MAX_ENVELOPE_ITEMS + 3)]
    aggregate = TraceBatch.model_construct(
        batch_id="batch-original",
        collected_at=NOW,
        collector_id="collector-1",
        collector_version="test",
        events=events,
        file_events=[],
        process_events=[],
    )

    count_chunks = split_trace_batch(aggregate)

    assert [event.trace_id for chunk in count_chunks for event in chunk.events] == [
        event.trace_id for event in events
    ]
    assert all(len(chunk.events) <= MAX_ENVELOPE_ITEMS for chunk in count_chunks)
    assert count_chunks[0].batch_id == aggregate.batch_id
    assert len({chunk.batch_id for chunk in count_chunks}) == len(count_chunks)
    assert all(
        TraceBatch.model_validate_json(chunk.model_dump_json()) == chunk for chunk in count_chunks
    )

    padded = TraceBatch(
        batch_id="batch-byte-limit",
        collected_at=NOW,
        collector_id="collector-1",
        collector_version="test",
        events=[_trace(index, padding=1_000) for index in range(7)],
    )
    byte_chunks = split_trace_batch(padded, max_bytes=3_000)
    assert len(byte_chunks) > 1
    assert [event.trace_id for chunk in byte_chunks for event in chunk.events] == [
        event.trace_id for event in padded.events
    ]
    assert all(len(chunk.model_dump_json().encode()) <= 3_000 for chunk in byte_chunks)


def test_analyzer_client_forwards_all_asset_chunks_with_private_identity() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/ingest/asset-report"
        assert request.headers["authorization"] == "Bearer analyzer-secret"
        payload = json.loads(request.content)
        seen.append(payload)
        return httpx.Response(202, json={"accepted": True, "id": payload["report_id"]})

    async def scenario() -> httpx.Response:
        client = AnalyzerClient(
            "http://analyzer.internal:10068",
            "analyzer-secret",
            transport=httpx.MockTransport(handler),
        )
        try:
            return await client.ingest_asset_report(_unbounded_report(MAX_ENVELOPE_ITEMS + 1))
        finally:
            await client.close()

    response = asyncio.run(scenario())

    assert response.json()["id"] == "report-original"
    assert len(seen) == 2
    assert sum(len(payload["assets"]) for payload in seen) == MAX_ENVELOPE_ITEMS + 1  # type: ignore[arg-type]
    assert max(len(payload["assets"]) for payload in seen) <= MAX_ENVELOPE_ITEMS  # type: ignore[arg-type]


def test_analyzer_client_aggregates_partial_child_derivation() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = json.loads(request.content)
        derived = "complete" if calls == 1 else "partial"
        return httpx.Response(
            202,
            json={
                "accepted": True,
                "id": payload["report_id"],
                "derived_status": derived,
                "derived_reason": "osv_sync_incomplete" if derived == "partial" else None,
            },
        )

    async def scenario() -> httpx.Response:
        client = AnalyzerClient("http://analyzer.internal", transport=httpx.MockTransport(handler))
        try:
            return await client.ingest_asset_report(_unbounded_report(MAX_ENVELOPE_ITEMS + 1))
        finally:
            await client.close()

    response = asyncio.run(scenario())
    assert response.extensions["kcatta_derived_status"] == "partial"
    assert response.extensions["kcatta_derived_reasons"] == ("osv_sync_incomplete",)


def test_analyzer_client_treats_pending_child_as_queued_not_failed() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = json.loads(request.content)
        return httpx.Response(
            202,
            json={
                "accepted": True,
                "queued": calls == 2,
                "id": payload["report_id"],
                "derived_status": "complete" if calls == 1 else "pending",
            },
        )

    async def scenario() -> httpx.Response:
        client = AnalyzerClient("http://analyzer.internal", transport=httpx.MockTransport(handler))
        try:
            return await client.ingest_asset_report(_unbounded_report(MAX_ENVELOPE_ITEMS + 1))
        finally:
            await client.close()

    response = asyncio.run(scenario())
    assert response.extensions["kcatta_derived_status"] == "pending"


def test_analyzer_client_rejects_accepted_but_failed_derivation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        return httpx.Response(
            202,
            json={
                "accepted": True,
                "id": payload["report_id"],
                "derived_status": "failed",
                "derived_reason": "derived_store_full",
            },
        )

    async def scenario() -> None:
        client = AnalyzerClient("http://analyzer.internal", transport=httpx.MockTransport(handler))
        try:
            await client.ingest_asset_report(_unbounded_report(1))
        finally:
            await client.close()

    with pytest.raises(AnalyzerUpstreamError, match="derived processing failed") as raised:
        asyncio.run(scenario())
    assert raised.value.status_code == 503


def test_correlation_identifier_bounding_is_unicode_safe_and_stable() -> None:
    assert bounded_correlation_id("short-id") == "short-id"
    value = "节点" * 300
    bounded = bounded_correlation_id(value)

    assert len(bounded) == 256
    assert "~sha256:" in bounded
    assert bounded == bounded_correlation_id(value)
    assert bounded.encode("utf-8").decode("utf-8") == bounded
