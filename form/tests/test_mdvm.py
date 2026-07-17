"""MDVM baseline/delta materialization and least-privilege transport tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from kcatta_form.analyzer_client import AnalyzerUpstreamError
from kcatta_form.mde import MdeHostMapper, MdeUpstreamError
from kcatta_form.mdvm import (
    MDVM_SCOPE,
    MdvmClient,
    MdvmConfig,
    MdvmSyncEngine,
    MdvmSyncState,
    normalize_mdvm_record,
)

NOW = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
TENANT = "00000000-0000-0000-0000-000000000001"
CLIENT = "00000000-0000-0000-0000-000000000002"


def _config(tmp_path: Path, **updates) -> MdvmConfig:  # type: ignore[no-untyped-def]
    secret = tmp_path / "mdvm-secret"
    secret.write_text("top-secret", encoding="utf-8")
    values = {
        "enabled": True,
        "tenant_id": TENANT,
        "client_id": CLIENT,
        "client_secret_file": secret,
        "state_path": tmp_path / "mdvm-state.db",
        "poll_seconds": 21_600.0,
        "baseline_refresh_hours": 168.0,
        "delta_overlap_seconds": 21_600.0,
        "timeout_seconds": 5.0,
        "page_size": 100,
        "max_pages": 5,
        "max_items": 100,
        "findings_per_snapshot": 10,
        "snapshots_per_batch": 10,
        "batch_max_bytes": 1024 * 1024,
        "max_attempts": 2,
    }
    values.update(updates)
    return MdvmConfig(**values)


def _row(*, status: str | None = None, event: datetime | None = None) -> dict:
    row = {
        "id": "record-1",
        "deviceId": "device-1",
        "deviceName": "win-1.contoso.test",
        "osPlatform": "Windows11",
        "osVersion": "24H2",
        "osArchitecture": "x64",
        "rbacGroupName": "Workstations",
        "softwareVendor": "contoso",
        "softwareName": "browser",
        "softwareVersion": "1.2.3",
        "cveId": "CVE-2026-12345",
        "vulnerabilitySeverityLevel": "High",
        "cvssScore": 8.1,
        "lastSeenTimestamp": NOW.isoformat(),
        "firstSeenTimestamp": NOW.isoformat(),
        "exploitabilityLevel": "ExploitIsPublic",
        "recommendedSecurityUpdateId": "KB12345",
        "securityUpdateAvailable": True,
    }
    if status is not None:
        row["status"] = status
    if event is not None:
        row["eventTimestamp"] = event.isoformat()
    return row


def test_disabled_mdvm_ignores_unused_invalid_tuning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORM_MDVM_ENABLED", "false")
    monkeypatch.setenv("FORM_MDVM_POLL_SECONDS", "bad")
    config = MdvmConfig.from_env(tmp_path)
    assert config.enabled is False
    assert not config.state_path.exists()


def test_client_uses_legacy_audience_and_only_export_gets(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "login.microsoftonline.com":
            assert b"api.securitycenter.microsoft.com" in request.content
            assert MDVM_SCOPE.endswith("/.default")
            return httpx.Response(200, json={"access_token": "token", "expires_in": 3600})
        assert request.method == "GET"
        assert request.url.path.endswith("SoftwareVulnerabilitiesByMachine")
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"value": [_row()]})
        return httpx.Response(
            200,
            json={
                "value": [_row()],
                "@odata.nextLink": (
                    "https://api.security.microsoft.com/api/machines/"
                    "SoftwareVulnerabilitiesByMachine?page=2"
                ),
            },
        )

    async def run() -> list[dict]:
        client = MdvmClient(_config(tmp_path), transport=httpx.MockTransport(handler))
        try:
            return await client.baseline()
        finally:
            await client.close()

    rows = asyncio.run(run())
    assert len(rows) == 2
    api_requests = [item for item in seen if item.url.host == "api.security.microsoft.com"]
    assert all(item.method == "GET" for item in api_requests)


def test_client_rejects_cross_origin_pagination(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "token"})
        return httpx.Response(
            200,
            json={"value": [], "@odata.nextLink": "https://attacker.invalid/export"},
        )

    async def run() -> None:
        client = MdvmClient(_config(tmp_path), transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(MdeUpstreamError, match="pagination URL"):
                await client.baseline()
        finally:
            await client.close()

    asyncio.run(run())


class _Mdvm:
    def __init__(self) -> None:
        self.delta_since: datetime | None = None

    async def baseline(self) -> list[dict]:
        return [_row()]

    async def delta(self, since: datetime) -> list[dict]:
        self.delta_since = since
        return [_row(status="Fixed", event=NOW + timedelta(hours=6))]


class _Analyzer:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.batches = []

    async def ingest(self, path, batch):  # type: ignore[no-untyped-def]
        if self.fail:
            raise AnalyzerUpstreamError("unavailable")
        assert path == "/ingest/mdvm-vulnerability-batch"
        self.batches.append(batch)
        response = httpx.Response(202, json={"accepted": True})
        response.extensions["kcatta_derived_status"] = "complete"
        return response


def test_baseline_then_fixed_delta_materializes_complete_zero_snapshot(tmp_path: Path) -> None:
    config = _config(tmp_path)
    state = MdvmSyncState(config.state_path)
    client = _Mdvm()
    analyzer = _Analyzer()
    engine = MdvmSyncEngine(config, client, analyzer, state)  # type: ignore[arg-type]

    baseline = asyncio.run(engine.sync_once(NOW))
    delta = asyncio.run(engine.sync_once(NOW + timedelta(hours=7)))

    assert baseline.mode == "baseline"
    assert baseline.findings == 1
    assert analyzer.batches[0].snapshots[0].host_id == "mde:device-1"
    assert analyzer.batches[0].snapshots[0].vulnerabilities[0].cve_id == "CVE-2026-12345"
    assert delta.mode == "delta"
    assert delta.findings == 0
    assert analyzer.batches[1].snapshots[0].vulnerabilities == []
    assert client.delta_since == NOW - timedelta(hours=6)
    snapshot = state.snapshot()
    assert snapshot["active_finding_count"] == 0
    assert snapshot["watermark"] == (NOW + timedelta(hours=7)).isoformat()
    state.close()


def test_analyzer_failure_keeps_mdvm_watermark_for_retry(tmp_path: Path) -> None:
    config = _config(tmp_path)
    state = MdvmSyncState(config.state_path)
    engine = MdvmSyncEngine(
        config,
        _Mdvm(),  # type: ignore[arg-type]
        _Analyzer(fail=True),
        state,
    )
    with pytest.raises(AnalyzerUpstreamError):
        asyncio.run(engine.sync_once(NOW))
    snapshot = state.snapshot()
    assert snapshot["watermark"] is None
    assert snapshot["active_finding_count"] == 0
    assert "AnalyzerUpstreamError" in snapshot["last_error"]
    state.close()


def test_same_time_active_and_fixed_delta_fails_closed(tmp_path: Path) -> None:
    state = MdvmSyncState(tmp_path / "mdvm-state.db")
    owner = "lease-owner"
    assert state.acquire(owner, NOW, 900)
    active = normalize_mdvm_record(
        _row(status="New", event=NOW), mode="delta", fallback_time=NOW
    )
    fixed = normalize_mdvm_record(
        _row(status="Fixed", event=NOW), mode="delta", fallback_time=NOW
    )
    assert active is not None and fixed is not None
    with pytest.raises(MdeUpstreamError, match="ambiguous"):
        state.apply_delta(owner, [active, fixed])
    state.close()


def test_materialized_state_capacity_rolls_back_baseline(tmp_path: Path) -> None:
    state = MdvmSyncState(tmp_path / "mdvm-state.db", max_findings=0)
    owner = "lease-owner"
    assert state.acquire(owner, NOW, 900)
    change = normalize_mdvm_record(_row(), mode="baseline", fallback_time=NOW)
    assert change is not None
    with pytest.raises(MdeUpstreamError, match="STATE_MAX_FINDINGS"):
        state.replace_baseline(owner, [change])
    snapshots = state.device_snapshots(
        {"device-1"},
        tenant_id=TENANT,
        mode="baseline",
        mapper=MdeHostMapper(),
        findings_per_snapshot=10,
    )
    assert snapshots == []
    state.close()
