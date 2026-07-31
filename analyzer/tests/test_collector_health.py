from __future__ import annotations

from datetime import UTC, datetime, timedelta

from analyzer.api.app import _check_collector_health_gaps, create_app
from analyzer.schemas import (
    ActionTaken,
    CollectorHealthEvent,
    CollectorHealthStatus,
    GuardEventBatch,
    Outcome,
    Severity,
)


def _batch(at: datetime, batch_id: str) -> GuardEventBatch:
    return GuardEventBatch(
        batch_id=batch_id,
        collected_at=at,
        host_id="target-1",
        agent_version="0.1.0",
        events=[
            CollectorHealthEvent(
                event_id=f"event-{batch_id}",
                timestamp=at,
                severity=Severity.INFO,
                host_id="target-1",
                action_taken=ActionTaken.LOGGED,
                outcome=Outcome.SUCCESS,
                component="agent-respond",
                status=CollectorHealthStatus.HEALTHY,
                message="guard sensors reporting",
            )
        ],
    )


def test_stale_heartbeat_alerts_once_and_rearms_after_recovery(tmp_path):
    app = create_app(
        data_dir=tmp_path / "data",
        osv_dir=tmp_path / "osv",
        debian_tracker_dir=tmp_path / "tracker",
        allow_insecure_no_auth=True,
    )
    base = datetime(2026, 7, 31, 0, 0, tzinfo=UTC)
    app.state.guard_event_store.append(_batch(base, "old"))

    assert (
        _check_collector_health_gaps(
            app,
            now=base + timedelta(seconds=301),
            gap_seconds=300,
        )
        == 1
    )
    assert (
        _check_collector_health_gaps(
            app,
            now=base + timedelta(seconds=400),
            gap_seconds=300,
        )
        == 0
    )
    alerts = app.state.alert_store.tail(10)
    assert len(alerts) == 1
    assert alerts[0]["alert_key"]
    assert "heartbeat missing" in alerts[0]["title"]

    recovered = base + timedelta(seconds=401)
    app.state.guard_event_store.append(_batch(recovered, "recovered"))
    assert (
        _check_collector_health_gaps(
            app,
            now=recovered,
            gap_seconds=300,
        )
        == 0
    )
    assert app.state.collector_gap_alerted == {}

    assert (
        _check_collector_health_gaps(
            app,
            now=recovered + timedelta(seconds=301),
            gap_seconds=300,
        )
        == 1
    )
    assert len(app.state.alert_store.tail(10)) == 2
