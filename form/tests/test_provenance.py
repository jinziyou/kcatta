from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kcatta_form.provenance import ProvenanceConflict, bind_agent_envelope, bind_form_envelope
from kcatta_form.schemas import AssetReport, GuardEventBatch, TraceBatch


def _asset() -> AssetReport:
    return AssetReport.model_validate(
        {
            "report_id": "report-1",
            "collected_at": datetime.now(UTC),
            "scanner_version": "1",
            "host": {"host_id": "claimed-host", "hostname": "node", "os": "Linux"},
            "vulnerabilities": [
                {
                    "vuln_id": "finding-1",
                    "source": "posture",
                    "severity": "high",
                    "affected_asset_id": "claimed-host",
                }
            ],
        }
    )


def test_agent_binding_overwrites_host_and_adds_authenticated_provenance() -> None:
    source = _asset()

    bound = bind_agent_envelope(
        source,
        agent_id="agent-1",
        target_id="target-1",
        canonical_host_id="target-1",
    )

    assert source.host.host_id == "claimed-host"
    assert bound.host.host_id == "target-1"
    assert bound.vulnerabilities[0].affected_asset_id == "target-1"
    assert bound.source_agent_id == "agent-1"
    assert bound.source_target_id == "target-1"


def test_agent_binding_rejects_conflicting_claimed_identity() -> None:
    source = _asset().model_copy(update={"source_agent_id": "agent-other"})

    with pytest.raises(ProvenanceConflict, match="source_agent_id"):
        bind_agent_envelope(
            source,
            agent_id="agent-1",
            target_id="target-1",
            canonical_host_id="target-1",
        )


def test_trace_and_guard_nested_hosts_are_canonicalized() -> None:
    now = datetime.now(UTC)
    trace = TraceBatch.model_validate(
        {
            "batch_id": "trace-1",
            "collected_at": now,
            "collector_id": "collector",
            "collector_version": "1",
            "events": [
                {
                    "trace_id": "event-1",
                    "host_id": "fake",
                    "start_ts": now,
                    "end_ts": now,
                    "proto": "tcp",
                    "src_ip": "127.0.0.1",
                    "dst_ip": "127.0.0.2",
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                }
            ],
        }
    )
    guard = GuardEventBatch.model_validate(
        {
            "batch_id": "guard-1",
            "collected_at": now,
            "host_id": "fake",
            "agent_version": "1",
            "events": [
                {
                    "kind": "fim",
                    "event_id": "event-1",
                    "timestamp": now,
                    "severity": "low",
                    "host_id": "fake",
                    "action_taken": "logged",
                    "outcome": "success",
                    "path": "/tmp/a",
                    "change_type": "modified",
                }
            ],
        }
    )

    bound_trace = bind_form_envelope(trace, target_id="target-1", canonical_host_id="target-1")
    bound_guard = bind_agent_envelope(
        guard,
        agent_id="agent-1",
        target_id="target-1",
        canonical_host_id="target-1",
    )

    assert bound_trace.events[0].host_id == "target-1"
    assert bound_guard.host_id == "target-1"
    assert bound_guard.events[0].host_id == "target-1"
