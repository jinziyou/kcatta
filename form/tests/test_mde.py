"""Read-only MDE Graph pagination, normalization and durable watermark tests."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from kcatta_form.analyzer_client import AnalyzerUpstreamError
from kcatta_form.mde import (
    MdeConfig,
    MdeGraphClient,
    MdeHostMapper,
    MdeSyncEngine,
    MdeSyncState,
    MdeUpstreamError,
    normalize_alert,
)

NOW = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
TENANT = "00000000-0000-0000-0000-000000000001"
CLIENT = "00000000-0000-0000-0000-000000000002"


def _config(tmp_path: Path, **updates) -> MdeConfig:  # type: ignore[no-untyped-def]
    secret = tmp_path / "mde-secret"
    secret.write_text("top-secret", encoding="utf-8")
    values = {
        "enabled": True,
        "tenant_id": TENANT,
        "client_id": CLIENT,
        "client_secret_file": secret,
        "state_path": tmp_path / "mde-state.db",
        "poll_seconds": 300.0,
        "initial_lookback_hours": 48.0,
        "overlap_seconds": 300.0,
        "timeout_seconds": 5.0,
        "page_size": 100,
        "max_pages": 5,
        "max_items": 100,
        "chunk_size": 128,
        "max_attempts": 2,
    }
    values.update(updates)
    return MdeConfig(**values)


def test_disabled_connector_ignores_unused_invalid_tuning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORM_MDE_ENABLED", "false")
    monkeypatch.setenv("FORM_MDE_POLL_SECONDS", "not-a-number")
    monkeypatch.setenv("FORM_MDE_CLIENT_SECRET", "must-never-be-read")

    config = MdeConfig.from_env(tmp_path)

    assert config.enabled is False
    assert config.client_secret_file is None
    assert not config.state_path.exists()


def test_graph_client_uses_read_gets_and_validates_next_link(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "token", "expires_in": 3600})
        assert request.method == "GET"
        assert request.headers["authorization"] == "Bearer token"
        if "page=2" in str(request.url):
            return httpx.Response(200, json={"value": [{"id": "a-2"}]})
        return httpx.Response(
            200,
            json={
                "value": [{"id": "a-1"}],
                "@odata.nextLink": (
                    "https://graph.microsoft.com/v1.0/security/alerts_v2?page=2"
                ),
            },
        )

    async def run() -> list[dict]:
        graph = MdeGraphClient(_config(tmp_path), transport=httpx.MockTransport(handler))
        try:
            return await graph.fetch("alerts_v2", NOW)
        finally:
            await graph.close()

    rows = asyncio.run(run())

    assert [row["id"] for row in rows] == ["a-1", "a-2"]
    graph_requests = [request for request in seen if request.url.host == "graph.microsoft.com"]
    assert all(request.method == "GET" for request in graph_requests)
    assert (
        graph_requests[0].url.params["$filter"]
        == "lastUpdateDateTime ge 2026-07-16T08:00:00Z"
    )


def test_graph_client_rejects_cross_origin_next_link(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "token"})
        return httpx.Response(
            200,
            json={"value": [], "@odata.nextLink": "https://attacker.invalid/steal"},
        )

    async def run() -> None:
        graph = MdeGraphClient(_config(tmp_path), transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(MdeUpstreamError, match="pagination URL"):
                await graph.fetch("alerts_v2", NOW)
        finally:
            await graph.close()

    asyncio.run(run())


def test_device_evidence_uses_explicit_mapping_then_isolated_fallback(tmp_path: Path) -> None:
    map_file = tmp_path / "host-map.json"
    map_file.write_text(json.dumps({"mde:machine-1": "host-windows-1"}), encoding="utf-8")
    mapper = MdeHostMapper.load(map_file)
    base = {
        "id": "alert-1",
        "title": "Detection",
        "status": "new",
        "severity": "high",
        "createdDateTime": NOW.isoformat(),
        "lastUpdateDateTime": NOW.isoformat(),
    }
    mapped = normalize_alert(
        {
            **base,
            "evidence": [
                {
                    "@odata.type": "#microsoft.graph.security.deviceEvidence",
                    "mdeDeviceId": "machine-1",
                }
            ],
        },
        mapper,
    )
    fallback = normalize_alert(
        {**base, "id": "alert-2", "evidence": [{"mdeDeviceId": "unknown-machine"}]},
        mapper,
    )

    assert mapped.related_asset_ids == ["host-windows-1"]
    assert fallback.related_asset_ids == ["mde:unknown-machine"]


class _Graph:
    async def fetch(self, resource: str, since: datetime):  # type: ignore[no-untyped-def]
        if resource == "alerts_v2":
            return [
                {
                    "id": "alert-1",
                    "incidentId": "incident-1",
                    "title": "Detection",
                    "status": "new",
                    "severity": "high",
                    "createdDateTime": NOW.isoformat(),
                    "lastUpdateDateTime": NOW.isoformat(),
                    "evidence": [{"mdeDeviceId": "machine-1"}],
                }
            ]
        return [
            {
                "id": "incident-1",
                "displayName": "Incident",
                "status": "active",
                "severity": "high",
                "createdDateTime": NOW.isoformat(),
                "lastUpdateDateTime": NOW.isoformat(),
                "alerts": [{"id": "alert-1"}],
            }
        ]


class _Analyzer:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.batches = []

    async def ingest(self, path, batch):  # type: ignore[no-untyped-def]
        if self.fail:
            raise AnalyzerUpstreamError("unavailable")
        assert path == "/ingest/mde-security-batch"
        self.batches.append(batch)
        response = httpx.Response(202, json={"accepted": True})
        response.extensions["kcatta_derived_status"] = "complete"
        return response


def test_watermark_advances_only_after_all_analyzer_batches_succeed(tmp_path: Path) -> None:
    config = _config(tmp_path)
    state = MdeSyncState(config.state_path)
    analyzer = _Analyzer()
    engine = MdeSyncEngine(config, _Graph(), analyzer, state)  # type: ignore[arg-type]
    outcome = asyncio.run(engine.sync_once(NOW))

    assert outcome.acquired is True
    assert outcome.alerts == 1
    assert outcome.incidents == 1
    assert outcome.batches == 1
    assert state.watermark() == NOW
    assert analyzer.batches[0].alerts[0].related_asset_ids == ["mde:machine-1"]
    state.close()


def test_failed_analyzer_delivery_keeps_watermark_for_retry(tmp_path: Path) -> None:
    config = _config(tmp_path)
    state = MdeSyncState(config.state_path)
    engine = MdeSyncEngine(config, _Graph(), _Analyzer(fail=True), state)  # type: ignore[arg-type]

    with pytest.raises(AnalyzerUpstreamError):
        asyncio.run(engine.sync_once(NOW))

    snapshot = state.snapshot()
    assert state.watermark() is None
    assert "AnalyzerUpstreamError" in snapshot["last_error"]
    state.close()
