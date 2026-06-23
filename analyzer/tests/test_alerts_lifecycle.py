"""CI2: alert lifecycle — content-derived identity, de-duplication, triage overlay.

Covers the pure read model (`merge_alerts`), the stable `alert_key` derivation in
correlation, and the HTTP triage path end-to-end (POST appends an AlertState that
the read layer overlays back onto the de-duplicated alert).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.correlate import correlate_trace_batch
from analyzer.correlate.lifecycle import merge_alerts
from analyzer.schemas import IndicatorType, Severity, ThreatMatch, TraceBatch, TraceEvent

NOW = datetime(2026, 5, 28, 10, 0, 0, tzinfo=UTC)


def _match(indicator: str = "93.184.216.34") -> ThreatMatch:
    return ThreatMatch(
        indicator=indicator,
        indicator_type=IndicatorType.IP,
        category="c2",
        severity=Severity.HIGH,
        source="builtin-demo",
    )


def _batch(batch_id: str, indicator: str = "93.184.216.34") -> TraceBatch:
    event = TraceEvent(
        trace_id=f"{batch_id}-f1",
        host_id="h-001",
        start_ts=NOW,
        end_ts=NOW,
        proto="tcp",
        src_ip="10.0.0.42",
        dst_ip=indicator,
        dst_port=443,
        bytes_sent=512,
        bytes_recv=2048,
        threat_intel=[_match(indicator)],
    )
    return TraceBatch(
        batch_id=batch_id,
        collected_at=NOW,
        collector_id="col-1",
        collector_version="0.1.0",
        events=[event],
    )


# --------------------------------------------------------------------------
# alert_key derivation
# --------------------------------------------------------------------------


def test_alert_key_is_stable_across_batches_but_alert_id_differs():
    a = correlate_trace_batch(_batch("b-1"))[0]
    b = correlate_trace_batch(_batch("b-2"))[0]
    # Same indicator → same content-derived key, regardless of batch.
    assert a.alert_key == b.alert_key
    assert a.alert_key and a.alert_key.startswith("ak-")
    # The per-occurrence id still carries the batch, so occurrences are distinct.
    assert a.alert_id != b.alert_id


def test_alert_key_differs_by_indicator():
    a = correlate_trace_batch(_batch("b-1", indicator="93.184.216.34"))[0]
    b = correlate_trace_batch(_batch("b-1", indicator="203.0.113.9"))[0]
    assert a.alert_key != b.alert_key


# --------------------------------------------------------------------------
# merge_alerts read model (pure)
# --------------------------------------------------------------------------


def _alert_row(alert_key: str, alert_id: str, created_at: str) -> dict:
    return {
        "alert_id": alert_id,
        "alert_key": alert_key,
        "severity": "high",
        "score": 75.0,
        "title": "t",
        "description": "d",
        "created_at": created_at,
    }


def test_merge_dedups_by_key_and_counts_occurrences():
    rows = [  # newest-first, as tail returns
        _alert_row("ak-x", "id-2", "2026-05-28T10:05:00Z"),
        _alert_row("ak-x", "id-1", "2026-05-28T10:00:00Z"),
    ]
    merged = merge_alerts(rows, [])
    assert len(merged) == 1
    assert merged[0].occurrence_count == 2
    # Newest occurrence supplies display fields + last_seen.
    assert merged[0].alert_id == "id-2"
    assert merged[0].last_seen is not None


def test_merge_applies_triage_overlay():
    rows = [_alert_row("ak-x", "id-1", "2026-05-28T10:00:00Z")]
    states = [
        {
            "alert_key": "ak-x",
            "status": "acknowledged",
            "assignee": "alice",
            "note": "investigating",
            "suppressed": False,
            "updated_at": "2026-05-28T11:00:00Z",
        }
    ]
    merged = merge_alerts(rows, states)
    assert merged[0].status == "acknowledged"
    assert merged[0].assignee == "alice"
    assert merged[0].note == "investigating"
    assert merged[0].updated_at is not None


def test_merge_hides_suppressed_unless_requested():
    rows = [_alert_row("ak-x", "id-1", "2026-05-28T10:00:00Z")]
    states = [
        {
            "alert_key": "ak-x",
            "status": "closed",
            "suppressed": True,
            "updated_at": NOW.isoformat(),
        }
    ]
    assert merge_alerts(rows, states) == []
    shown = merge_alerts(rows, states, include_suppressed=True)
    assert len(shown) == 1 and shown[0].suppressed is True


def test_merge_newest_state_wins():
    rows = [_alert_row("ak-x", "id-1", "2026-05-28T10:00:00Z")]
    states = [  # newest-first
        {"alert_key": "ak-x", "status": "closed", "updated_at": "2026-05-28T12:00:00Z"},
        {"alert_key": "ak-x", "status": "acknowledged", "updated_at": "2026-05-28T11:00:00Z"},
    ]
    assert merge_alerts(rows, states)[0].status == "closed"


# --------------------------------------------------------------------------
# HTTP triage end-to-end
# --------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(data_dir=tmp_path)
    with TestClient(app) as test_client:
        yield test_client, app


def _ingest(c: TestClient, batch: TraceBatch) -> None:
    resp = c.post("/ingest/trace-batch", json=batch.model_dump(mode="json"))
    assert resp.status_code == 202, resp.text


def _only_alert(c: TestClient) -> dict:
    alerts = c.get("/reports/alerts").json()
    assert len(alerts) == 1, alerts
    return alerts[0]


def test_list_dedups_occurrences_across_batches(client):
    c, _ = client
    _ingest(c, _batch("b-1"))
    _ingest(c, _batch("b-2"))  # same indicator, distinct batch
    alert = _only_alert(c)
    assert alert["occurrence_count"] == 2
    assert alert["alert_key"].startswith("ak-")


def test_triage_sets_status_and_assignee_and_note(client):
    c, _ = client
    _ingest(c, _batch("b-1"))
    key = _only_alert(c)["alert_key"]

    resp = c.post(
        f"/reports/alerts/{key}/triage",
        json={"status": "acknowledged", "assignee": "alice", "note": "looking into it"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "acknowledged"
    assert body["assignee"] == "alice"
    assert body["note"] == "looking into it"

    # Persisted: a fresh GET reflects the overlay.
    after = _only_alert(c)
    assert after["status"] == "acknowledged"
    assert after["assignee"] == "alice"


def test_triage_partial_update_preserves_prior_fields(client):
    c, _ = client
    _ingest(c, _batch("b-1"))
    key = _only_alert(c)["alert_key"]

    c.post(f"/reports/alerts/{key}/triage", json={"status": "acknowledged"})
    # A later update that only sets assignee must keep the earlier status.
    resp = c.post(f"/reports/alerts/{key}/triage", json={"assignee": "bob"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "acknowledged"
    assert body["assignee"] == "bob"


def test_triage_suppress_hides_from_default_list(client):
    c, _ = client
    _ingest(c, _batch("b-1"))
    key = _only_alert(c)["alert_key"]

    c.post(f"/reports/alerts/{key}/triage", json={"suppressed": True})
    assert c.get("/reports/alerts").json() == []
    # Still visible (and marked) when explicitly requested.
    with_suppressed = c.get("/reports/alerts", params={"include_suppressed": "true"}).json()
    assert len(with_suppressed) == 1
    assert with_suppressed[0]["suppressed"] is True


def test_triage_unknown_alert_key_404(client):
    c, _ = client
    resp = c.post("/reports/alerts/ak-nope/triage", json={"status": "closed"})
    assert resp.status_code == 404


def test_triage_empty_body_422(client):
    c, _ = client
    _ingest(c, _batch("b-1"))
    key = _only_alert(c)["alert_key"]
    resp = c.post(f"/reports/alerts/{key}/triage", json={})
    assert resp.status_code == 422


def test_get_alert_by_occurrence_id_returns_merged(client):
    c, _ = client
    _ingest(c, _batch("b-1"))
    alert = _only_alert(c)
    fetched = c.get(f"/reports/alerts/{alert['alert_id']}").json()
    assert fetched["alert_key"] == alert["alert_key"]
    assert fetched["occurrence_count"] == 1
