"""Explicit execution mode (ScanMode) + resident guard daemon lifecycle.

ScanMode is derived from capability and must read back on historical job rows.
The guard stop/status SSH layer is exercised with a fake session; the API layer
monkeypatches the deploy wrappers so no real target is needed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.deploy import agent as deploy_agent
from analyzer.deploy.agent import GuardStatus
from analyzer.schemas import ScanCapability, ScanJob, ScanMode, mode_for_capability

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


# ---- ScanMode --------------------------------------------------------------


@pytest.mark.parametrize(
    ("capability", "mode"),
    [
        (ScanCapability.HOST, ScanMode.ONESHOT),
        (ScanCapability.TRACE, ScanMode.ONESHOT),
        (ScanCapability.GUARD, ScanMode.RESIDENT),
    ],
)
def test_mode_for_capability(capability, mode):
    assert mode_for_capability(capability) == mode


def _job(capability: ScanCapability, **kw) -> ScanJob:
    return ScanJob(
        job_id="j", target_id="t", address="root@h", capability=capability, created_at=NOW, **kw
    )


def test_scan_job_derives_mode():
    assert _job(ScanCapability.GUARD).mode == ScanMode.RESIDENT
    assert _job(ScanCapability.HOST).mode == ScanMode.ONESHOT


def test_scan_job_back_compat_old_row_without_mode():
    # A historical persisted row carried no `mode` → it reads back derived, not null.
    row = {
        "job_id": "j",
        "target_id": "t",
        "address": "root@h",
        "capability": "guard",
        "state": "succeeded",
        "created_at": NOW.isoformat(),
    }
    assert ScanJob.model_validate(row).mode == ScanMode.RESIDENT


def test_scan_job_explicit_mode_preserved():
    # An explicit mode is not overwritten by the derive validator.
    assert _job(ScanCapability.GUARD, mode=ScanMode.ONESHOT).mode == ScanMode.ONESHOT


# ---- guard stop over a session ---------------------------------------------


class _FakeResult:
    def __init__(self, stdout: str = "", stderr: str = "") -> None:
        self.stdout = stdout
        self.stderr = stderr


class _RecordingSession:
    """Serves scripted responses by regex (first match wins) and records commands."""

    def __init__(self, responses: list[tuple[str, str]]) -> None:
        self._responses = responses
        self.commands: list[str] = []

    def exec(self, cmd: str) -> _FakeResult:
        self.commands.append(cmd)
        for pattern, stdout in self._responses:
            if re.search(pattern, cmd):
                return _FakeResult(stdout)
        return _FakeResult("")


def test_guard_stop_over_anchored_pkill_and_reports_dead():
    # Teardown then a re-probe that reports the unit inactive → alive=False.
    session = _RecordingSession([(r"rm -rf", "__stopped\n"), (r"is-active", "__active=inactive\n")])
    status = deploy_agent._guard_stop_over(session, "kcatta-guard", "/var/lib/agent-guard")
    assert status.alive is False
    teardown = session.commands[0]
    assert "systemctl stop" in teardown
    assert "rm -rf" in teardown
    # Path-anchored + bracketed pkill: matches THIS install's daemon, not its own line.
    assert "[/]var/lib/agent-guard/agentd respond" in teardown
    assert "[/]var/lib/agent-guard/agentd guard" in teardown  # legacy alias form
    assert "pkill -f 'agentd respond'" not in teardown  # not the old unanchored form


def test_guard_stop_over_reports_alive_when_daemon_survives():
    # The re-probe says the unit is still active → stop is reported honestly, not faked dead.
    session = _RecordingSession(
        [(r"rm -rf", "__stopped\n"), (r"is-active", "__active=active\n__pid=4242\n")]
    )
    status = deploy_agent._guard_stop_over(session, "kcatta-guard", "/var/lib/agent-guard")
    assert status.alive is True
    assert status.pid == "4242"
    assert "still reported alive" in status.detail


def test_guard_stop_over_raises_without_marker():
    session = _RecordingSession([(r"rm -rf", "boom")])
    with pytest.raises(RuntimeError, match="failed to stop"):
        deploy_agent._guard_stop_over(session, "kcatta-guard", "/var/lib/agent-guard")


# ---- guard lifecycle API ---------------------------------------------------


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("ANALYZER_API_TOKEN", raising=False)
    with TestClient(create_app()) as c:
        yield c


def _register_ssh(client) -> str:
    r = client.post("/targets", json={"name": "t", "address": "root@10.0.0.1", "transport": "ssh"})
    assert r.status_code == 201, r.text
    return r.json()["target_id"]


def test_guard_status_endpoint(client, monkeypatch: pytest.MonkeyPatch):
    tid = _register_ssh(client)
    monkeypatch.setattr(
        "analyzer.deploy.trigger.guard_status_for",
        lambda target: GuardStatus(
            alive=True, supervisor="systemd", detail="unit kcatta-guard is active", pid="42"
        ),
    )
    body = client.get(f"/targets/{tid}/guard").json()
    assert body["alive"] is True
    assert body["supervisor"] == "systemd"
    assert body["pid"] == "42"
    assert body["target_id"] == tid


def test_guard_status_unreachable_degrades(client, monkeypatch: pytest.MonkeyPatch):
    tid = _register_ssh(client)

    def boom(target):
        raise RuntimeError("no route to host")

    monkeypatch.setattr("analyzer.deploy.trigger.guard_status_for", boom)
    body = client.get(f"/targets/{tid}/guard").json()
    assert body["alive"] is False
    assert "cannot reach" in body["detail"]


def test_guard_status_rejects_non_ssh(client):
    r = client.post("/targets", json={"name": "loc", "address": "localhost", "transport": "local"})
    tid = r.json()["target_id"]
    res = client.get(f"/targets/{tid}/guard")
    assert res.status_code == 400
    assert "SSH targets" in res.json()["detail"]


def test_guard_status_unknown_target_404(client):
    assert client.get("/targets/target-nope/guard").status_code == 404


def test_guard_stop_endpoint(client, monkeypatch: pytest.MonkeyPatch):
    tid = _register_ssh(client)
    monkeypatch.setattr(
        "analyzer.deploy.trigger.stop_guard_for",
        lambda target: GuardStatus(alive=False, supervisor="unknown", detail="stopped"),
    )
    body = client.post(f"/targets/{tid}/guard/stop").json()
    assert body["alive"] is False
    assert body["detail"] == "stopped"


def test_guard_stop_failure_returns_502(client, monkeypatch: pytest.MonkeyPatch):
    tid = _register_ssh(client)

    def boom(target):
        raise RuntimeError("ssh down")

    monkeypatch.setattr("analyzer.deploy.trigger.stop_guard_for", boom)
    res = client.post(f"/targets/{tid}/guard/stop")
    assert res.status_code == 502
    assert "failed to stop" in res.json()["detail"]
