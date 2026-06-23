"""CI3: guard event cross-source correlation.

Guard network IOC hits / malware / high-severity IDS become Alerts; a compound
alert fires when a detection lands on a host with high/critical CVE posture. A
guard network IOC hit shares the trace IOC ``alert_key``, so a C2 seen by both
the guard and the network tap folds into one alert.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.correlate import (
    correlate_guard_batch,
    correlate_trace_batch,
    guard_compound_alerts,
)
from analyzer.schemas import (
    ActionTaken,
    DetectionResult,
    GuardEventBatch,
    IdsEvent,
    IndicatorType,
    MalwareEvent,
    NetworkEvent,
    Outcome,
    Severity,
    ThreatMatch,
    TraceBatch,
    TraceEvent,
    Vulnerability,
)

NOW = datetime(2026, 5, 28, 10, 0, 0, tzinfo=UTC)
C2_IP = "203.0.113.5"


def _net_event(severity: Severity = Severity.HIGH, indicator: str = C2_IP) -> NetworkEvent:
    return NetworkEvent(
        event_id="e-net",
        timestamp=NOW,
        severity=severity,
        host_id="h-001",
        action_taken=ActionTaken.BLOCKED_CONNECTION,
        outcome=Outcome.SUCCESS,
        proto="tcp",
        src_ip="10.0.0.2",
        src_port=54321,
        dst_ip=indicator,
        dst_port=443,
        indicator=indicator,
        indicator_type=IndicatorType.IP,
        category="c2",
        source="abuse.ch-feodo",
    )


def _malware_event() -> MalwareEvent:
    return MalwareEvent(
        event_id="e-mal",
        timestamp=NOW,
        severity=Severity.CRITICAL,
        host_id="h-001",
        action_taken=ActionTaken.QUARANTINED,
        outcome=Outcome.SUCCESS,
        path="/tmp/evil",
        signature="EICAR-Test-File",
        source="kcatta-malware",
    )


def _ids_event(severity: Severity) -> IdsEvent:
    return IdsEvent(
        event_id="e-ids",
        timestamp=NOW,
        severity=severity,
        host_id="h-001",
        action_taken=ActionTaken.LOGGED,
        outcome=Outcome.SUCCESS,
        signature_id="ET-2001",
        signature_name="ET TROJAN suspicious",
        proto="tcp",
        src_ip="10.0.0.2",
        dst_ip=C2_IP,
    )


def _guard_batch(events: list, batch_id: str = "g-1") -> GuardEventBatch:
    return GuardEventBatch(
        batch_id=batch_id,
        collected_at=NOW,
        host_id="h-001",
        agent_version="0.1.0",
        events=events,
    )


# --------------------------------------------------------------------------
# base guard alerts
# --------------------------------------------------------------------------


def test_network_event_alert_folds_with_trace_ioc_key():
    guard = correlate_guard_batch(_guard_batch([_net_event()]))
    assert len(guard) == 1
    g = guard[0]
    assert g.severity == Severity.HIGH
    assert g.related_asset_ids == ["h-001"]  # native host join

    # A trace IOC hit on the same indicator derives the SAME alert_key → folds.
    trace = correlate_trace_batch(
        TraceBatch(
            batch_id="b-1",
            collected_at=NOW,
            collector_id="c",
            collector_version="0.1.0",
            events=[
                TraceEvent(
                    trace_id="f-1",
                    host_id="h-001",
                    start_ts=NOW,
                    end_ts=NOW,
                    proto="tcp",
                    src_ip="10.0.0.2",
                    dst_ip=C2_IP,
                    dst_port=443,
                    bytes_sent=512,
                    bytes_recv=2048,
                    threat_intel=[
                        ThreatMatch(
                            indicator=C2_IP,
                            indicator_type=IndicatorType.IP,
                            category="c2",
                            severity=Severity.HIGH,
                            source="builtin",
                        )
                    ],
                )
            ],
        )
    )
    assert g.alert_key == trace[0].alert_key


def test_malware_event_becomes_alert():
    alerts = correlate_guard_batch(_guard_batch([_malware_event()]))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL
    assert "EICAR-Test-File" in alerts[0].title
    assert alerts[0].alert_key.startswith("ak-")


def test_high_severity_ids_alerts_but_low_does_not():
    assert len(correlate_guard_batch(_guard_batch([_ids_event(Severity.HIGH)]))) == 1
    assert correlate_guard_batch(_guard_batch([_ids_event(Severity.LOW)])) == []


def test_distinct_event_kinds_keep_distinct_keys():
    alerts = correlate_guard_batch(_guard_batch([_net_event(), _malware_event()]))
    keys = {a.alert_key for a in alerts}
    assert len(keys) == 2


# --------------------------------------------------------------------------
# compound alerts (guard detection on a high-CVE host)
# --------------------------------------------------------------------------


def _detection(host_id: str = "h-001", severity: Severity = Severity.CRITICAL) -> DetectionResult:
    return DetectionResult(
        report_id="r-1",
        host_id=host_id,
        collected_at=NOW,
        ecosystem="Debian:12",
        vulnerabilities=[
            Vulnerability(
                vuln_id="CVE-2099-0001",
                severity=severity,
                affected_asset_id="pkg-1",
                source="osv",
                evidence="x",
            )
        ],
    )


def test_compound_alert_when_guard_host_has_high_cve():
    guard = correlate_guard_batch(_guard_batch([_net_event()]))
    compound = guard_compound_alerts("g-1", NOW, guard, [_detection()])
    assert len(compound) == 1
    assert compound[0].related_vuln_ids == ["CVE-2099-0001"]
    assert "h-001" in compound[0].title


def test_no_compound_when_host_has_no_high_cve():
    guard = correlate_guard_batch(_guard_batch([_net_event()]))
    assert guard_compound_alerts("g-1", NOW, guard, [_detection(severity=Severity.LOW)]) == []


# --------------------------------------------------------------------------
# ingest integration
# --------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(data_dir=tmp_path)
    with TestClient(app) as test_client:
        yield test_client, app


def test_ingest_guard_event_raises_alert(client):
    c, _ = client
    batch = _guard_batch([_net_event()])
    assert c.post("/ingest/guard-event", json=batch.model_dump(mode="json")).status_code == 202
    alerts = c.get("/reports/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["related_asset_ids"] == ["h-001"]


def test_guard_and_trace_hit_on_same_indicator_fold_to_one(client):
    c, _ = client
    # Trace tap sees the C2 ...
    trace = TraceBatch(
        batch_id="b-1",
        collected_at=NOW,
        collector_id="c",
        collector_version="0.1.0",
        events=[
            TraceEvent(
                trace_id="f-1",
                host_id="h-001",
                start_ts=NOW,
                end_ts=NOW,
                proto="tcp",
                src_ip="10.0.0.2",
                dst_ip=C2_IP,
                dst_port=443,
                bytes_sent=512,
                bytes_recv=2048,
                threat_intel=[
                    ThreatMatch(
                        indicator=C2_IP,
                        indicator_type=IndicatorType.IP,
                        category="c2",
                        severity=Severity.HIGH,
                        source="builtin",
                    )
                ],
            )
        ],
    )
    c.post("/ingest/trace-batch", json=trace.model_dump(mode="json"))
    # ... and the guard on the host blocks the same C2.
    c.post("/ingest/guard-event", json=_guard_batch([_net_event()]).model_dump(mode="json"))

    alerts = c.get("/reports/alerts").json()
    assert len(alerts) == 1, alerts  # folded by shared alert_key
    assert alerts[0]["occurrence_count"] == 2


def test_ingest_guard_compound_with_existing_detection(client):
    c, app = client
    app.state.vulnerability_store.append(_detection())
    c.post("/ingest/guard-event", json=_guard_batch([_net_event()]).model_dump(mode="json"))
    alerts = c.get("/reports/alerts", params={"limit": "50"}).json()
    # Base guard alert + a compound alert referencing the host's CVE.
    assert any(a.get("related_vuln_ids") == ["CVE-2099-0001"] for a in alerts), alerts
