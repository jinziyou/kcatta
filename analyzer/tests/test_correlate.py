"""Tests for flow -> alert correlation."""

from __future__ import annotations

from datetime import UTC, datetime

from analyzer.correlate import correlate_trace_batch, cross_source_alerts, score_for_severity
from analyzer.schemas import (
    DetectionResult,
    IndicatorType,
    Severity,
    ThreatMatch,
    TraceBatch,
    TraceEvent,
    Vulnerability,
)

NOW = datetime(2026, 5, 28, 10, 0, 0, tzinfo=UTC)


def _flow(trace_id: str, matches: list[ThreatMatch], host_id: str = "h-001") -> TraceEvent:
    return TraceEvent(
        trace_id=trace_id,
        host_id=host_id,
        start_ts=NOW,
        end_ts=NOW,
        proto="tcp",
        src_ip="10.0.0.42",
        dst_ip="93.184.216.34",
        dst_port=443,
        bytes_sent=512,
        bytes_recv=2048,
        threat_intel=matches,
    )


def _batch(events: list[TraceEvent]) -> TraceBatch:
    return TraceBatch(
        batch_id="b-1",
        collected_at=NOW,
        collector_id="col-1",
        collector_version="0.1.0",
        events=events,
    )


def _match(severity: Severity, indicator: str = "93.184.216.34") -> ThreatMatch:
    return ThreatMatch(
        indicator=indicator,
        indicator_type=IndicatorType.IP,
        category="c2",
        severity=severity,
        source="builtin-demo",
    )


def test_no_matches_yields_no_alerts():
    batch = _batch([_flow("f-1", [])])
    assert correlate_trace_batch(batch) == []


def test_single_indicator_single_flow():
    batch = _batch([_flow("f-1", [_match(Severity.HIGH)]), _flow("f-2", [])])
    alerts = correlate_trace_batch(batch)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.related_trace_ids == ["f-1"]
    assert alert.related_asset_ids == ["h-001"]
    assert alert.severity == Severity.HIGH
    assert alert.score == score_for_severity(Severity.HIGH)
    assert alert.created_at == NOW


def test_alert_id_is_deterministic():
    batch = _batch([_flow("f-1", [_match(Severity.HIGH)])])
    first = correlate_trace_batch(batch)[0]
    second = correlate_trace_batch(batch)[0]
    assert first.alert_id == second.alert_id == "alert-ioc-b-1-ip-93.184.216.34"


def test_flows_hitting_same_indicator_merge_into_one_alert():
    batch = _batch(
        [
            _flow("f-1", [_match(Severity.LOW)], host_id="h-001"),
            _flow("f-2", [_match(Severity.CRITICAL)], host_id="h-002"),
        ]
    )
    alerts = correlate_trace_batch(batch)
    assert len(alerts) == 1, "same indicator -> one aggregated alert"
    alert = alerts[0]
    assert alert.related_trace_ids == ["f-1", "f-2"]
    assert alert.related_asset_ids == ["h-001", "h-002"]
    assert alert.severity == Severity.CRITICAL, "worst severity across the indicator's hits"


def test_one_flow_hitting_distinct_indicators_yields_multiple_alerts():
    flow = _flow(
        "f-1",
        [_match(Severity.HIGH, "1.1.1.1"), _match(Severity.MEDIUM, "2.2.2.2")],
    )
    alerts = correlate_trace_batch(_batch([flow]))
    assert len(alerts) == 2
    assert {a.related_trace_ids[0] for a in alerts} == {"f-1"}
    assert {a.severity for a in alerts} == {Severity.HIGH, Severity.MEDIUM}


# --- cross-source correlation ---


def _detection(host_id: str, severity: Severity, vuln_id: str = "CVE-2024-0001") -> DetectionResult:
    return DetectionResult(
        report_id="r-1",
        host_id=host_id,
        collected_at=NOW,
        ecosystem="Debian",
        vulnerabilities=[
            Vulnerability(
                vuln_id=vuln_id,
                severity=severity,
                affected_asset_id="pkg-1",
                source="osv",
            )
        ],
    )


def test_cross_source_skipped_without_high_risk_vulns():
    batch = _batch([_flow("f-1", [_match(Severity.HIGH)])])
    ioc = correlate_trace_batch(batch)
    cross = cross_source_alerts(batch.batch_id, batch.collected_at, ioc, [])
    assert cross == []


def test_cross_source_emits_when_host_has_critical_vuln():
    batch = _batch([_flow("f-1", [_match(Severity.HIGH)])])
    ioc = correlate_trace_batch(batch)
    detections = [_detection("h-001", Severity.CRITICAL)]
    cross = cross_source_alerts(batch.batch_id, batch.collected_at, ioc, detections)
    assert len(cross) == 1
    alert = cross[0]
    assert alert.alert_id == f"alert-cross-b-1-{ioc[0].alert_id}"
    assert alert.severity == Severity.CRITICAL
    assert alert.related_vuln_ids == ["CVE-2024-0001"]
    assert alert.related_trace_ids == ["f-1"]


def test_cross_source_worst_host_severity_uses_rank_not_string_order():
    """Regression: Severity is a StrEnum, so a plain max() would pick 'high' over
    'critical' (alphabetical). A critical+high host pair must yield critical."""
    batch = _batch(
        [
            _flow("f-1", [_match(Severity.LOW)], host_id="h-1"),
            _flow("f-2", [_match(Severity.LOW)], host_id="h-2"),
        ]
    )
    ioc = correlate_trace_batch(batch)
    detections = [
        _detection("h-1", Severity.CRITICAL, vuln_id="CVE-2024-0001"),
        _detection("h-2", Severity.HIGH, vuln_id="CVE-2024-0002"),
    ]
    cross = cross_source_alerts(batch.batch_id, batch.collected_at, ioc, detections)
    assert len(cross) == 1
    alert = cross[0]
    assert alert.severity == Severity.CRITICAL
    assert alert.score == score_for_severity(Severity.CRITICAL)


def test_cross_source_ignored_for_medium_vuln_only():
    batch = _batch([_flow("f-1", [_match(Severity.HIGH)])])
    ioc = correlate_trace_batch(batch)
    detections = [_detection("h-001", Severity.MEDIUM)]
    assert cross_source_alerts(batch.batch_id, batch.collected_at, ioc, detections) == []
