"""Form execution mode (ScanMode) + resident guard daemon lifecycle.

ScanMode is derived from capability and must read back on historical job rows.
The guard stop/status SSH layer is exercised with a fake session; the API layer
monkeypatches the deploy wrappers so no real target is needed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from kcatta_form.api import create_app
from kcatta_form.api import scans as scan_api
from kcatta_form.deploy import agent as deploy_agent
from kcatta_form.deploy.agent import GuardStatus
from kcatta_form.schemas import ScanCapability, ScanJob, ScanMode, mode_for_capability

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    ["", "http://127.0.0.1:10067", "http://[::1]:10067", "http://localhost:10067"],
)
def test_guard_public_url_rejects_missing_or_loopback(monkeypatch, value):
    monkeypatch.setenv("FORM_PUBLIC_URL", value)
    with pytest.raises(ValueError, match="FORM_PUBLIC_URL"):
        scan_api._public_url()


def test_guard_public_url_accepts_remote_https(monkeypatch):
    monkeypatch.setenv("FORM_PUBLIC_URL", "https://form.example.test/")
    assert scan_api._public_url() == "https://form.example.test"


def test_mtls_guard_public_url_accepts_only_https_origin(monkeypatch):
    monkeypatch.setenv("FORM_AGENT_PUBLIC_URL", "https://agents.example.test:10443/")
    assert scan_api._public_url(agent_identity=True) == "https://agents.example.test:10443"


@pytest.mark.parametrize(
    "value",
    [
        "https://agents.example.test/ingest",
        "https://agents.example.test//",
        "https://agents.example.test?tenant=one",
        "https://agents.example.test?",
        "https://agents.example.test#fragment",
        "https://agent@agents.example.test",
        "http://agents.example.test:10443",
    ],
)
def test_mtls_guard_public_url_rejects_non_origin_components(monkeypatch, value):
    monkeypatch.setenv("FORM_AGENT_PUBLIC_URL", value)
    monkeypatch.setenv("FORM_ALLOW_INSECURE_HTTP", "true")

    with pytest.raises(ValueError, match="FORM_AGENT_PUBLIC_URL"):
        scan_api._public_url(agent_identity=True)


def test_mtls_guard_never_falls_back_to_legacy_control_url(monkeypatch):
    monkeypatch.delenv("FORM_AGENT_PUBLIC_URL", raising=False)
    monkeypatch.setenv("FORM_PUBLIC_URL", "https://form.example.test:10067")

    with pytest.raises(ValueError, match="FORM_AGENT_PUBLIC_URL is required"):
        scan_api._public_url(agent_identity=True)


def test_guard_public_url_rejects_remote_plain_http_by_default(monkeypatch):
    monkeypatch.setenv("FORM_PUBLIC_URL", "http://192.0.2.8:10067")
    monkeypatch.delenv("FORM_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(ValueError, match="must use HTTPS"):
        scan_api._public_url()


def test_guard_public_url_allows_explicit_isolated_lab_http(monkeypatch):
    monkeypatch.setenv("FORM_PUBLIC_URL", "http://192.0.2.8:10067")
    monkeypatch.setenv("FORM_ALLOW_INSECURE_HTTP", "true")
    assert scan_api._public_url() == "http://192.0.2.8:10067"


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
    def __init__(self, stdout: str = "", stderr: str = "", status: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.status = status

    @property
    def success(self) -> bool:
        return self.status == 0


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
        [
            (r"rm -rf", "__stopped\n"),
            (r"is-active", "__active=active\n__pid=4242\n__ready=4242\n"),
        ]
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
    monkeypatch.setenv("FORM_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("FORM_API_TOKEN", raising=False)
    with TestClient(create_app()) as c:
        yield c


def _register_ssh(client) -> str:
    r = client.post("/targets", json={"name": "t", "address": "root@10.0.0.1", "transport": "ssh"})
    assert r.status_code == 201, r.text
    return r.json()["target_id"]


def _install_identity_service(
    client,
    events: list[str],
    *,
    revocation_error: Exception | None = None,
) -> None:
    class Repository:
        def get_by_target(self, target_id: str):  # type: ignore[no-untyped-def]
            events.append(f"lookup:{target_id}")
            return SimpleNamespace(agent_id="agent-stable")

        def close(self) -> None:
            pass

    class IdentityService:
        repository = Repository()

        def revoke_certificates(self, agent_id: str):  # type: ignore[no-untyped-def]
            events.append(f"revoke:{agent_id}")
            if revocation_error is not None:
                raise revocation_error

    client.app.state.agent_identity_service = IdentityService()


def test_guard_status_endpoint(client, monkeypatch: pytest.MonkeyPatch):
    tid = _register_ssh(client)
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_status_for",
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

    monkeypatch.setattr("kcatta_form.deploy.trigger.guard_status_for", boom)
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


def test_guard_without_public_url_is_rejected_without_persisting_ghost_job(
    client, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("FORM_PUBLIC_URL", raising=False)
    tid = _register_ssh(client)

    response = client.post(
        "/scans",
        json={"target_id": tid, "capability": "guard", "options": {}},
    )

    assert response.status_code == 503
    assert "FORM_PUBLIC_URL" in response.json()["detail"]
    assert client.get("/scans").json() == []


def test_guard_without_ingest_token_never_falls_back_to_control_or_persists_job(
    client, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("FORM_PUBLIC_URL", "https://form.example.test")
    tid = _register_ssh(client)
    client.app.state.api_token = "control-token-must-never-reach-guard"
    client.app.state.ingest_token = None
    headers = {"Authorization": "Bearer control-token-must-never-reach-guard"}

    response = client.post(
        "/scans",
        json={"target_id": tid, "capability": "guard", "options": {}},
        headers=headers,
    )

    assert response.status_code == 503
    assert "FORM_INGEST_TOKEN" in response.json()["detail"]
    assert client.get("/scans", headers=headers).json() == []


def test_trace_pcap_without_custom_binary_opt_in_is_rejected_without_ghost_job(
    client, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("FORM_TRACE_PCAP_ENABLED", raising=False)
    tid = _register_ssh(client)

    response = client.post(
        "/scans",
        json={"target_id": tid, "capability": "trace", "options": {"pcap": True}},
    )

    assert response.status_code == 422
    assert "FORM_TRACE_PCAP_ENABLED=true" in response.json()["detail"]
    assert client.get("/scans").json() == []


def test_guard_stop_endpoint(client, monkeypatch: pytest.MonkeyPatch):
    tid = _register_ssh(client)
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.stop_guard_for",
        lambda target: GuardStatus(alive=False, supervisor="unknown", detail="stopped"),
    )
    body = client.post(f"/targets/{tid}/guard/stop").json()
    assert body["alive"] is False
    assert body["detail"] == "stopped"


def test_guard_stop_revokes_credentials_but_keeps_stable_identity(
    client, monkeypatch: pytest.MonkeyPatch
):
    tid = _register_ssh(client)
    events: list[str] = []
    _install_identity_service(client, events)

    def stop(target):  # type: ignore[no-untyped-def]
        events.append("stop")
        return GuardStatus(alive=False, supervisor="unknown", detail="stopped")

    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.stop_guard_for",
        stop,
    )

    response = client.post(f"/targets/{tid}/guard/stop")

    assert response.status_code == 200
    assert events == [f"lookup:{tid}", "revoke:agent-stable", "stop"]


def test_guard_stop_revokes_before_unreachable_remote_error(
    client, monkeypatch: pytest.MonkeyPatch
):
    tid = _register_ssh(client)
    events: list[str] = []
    _install_identity_service(client, events)

    def unreachable(target):  # type: ignore[no-untyped-def]
        events.append("stop")
        raise RuntimeError("no route to host")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", unreachable)

    response = client.post(f"/targets/{tid}/guard/stop")

    assert response.status_code == 502
    assert response.json()["detail"] == "failed to stop guard daemon: no route to host"
    assert events == [f"lookup:{tid}", "revoke:agent-stable", "stop"]


def test_guard_stop_revokes_before_remote_guard_respawns(client, monkeypatch: pytest.MonkeyPatch):
    tid = _register_ssh(client)
    events: list[str] = []
    _install_identity_service(client, events)

    def respawned(target):  # type: ignore[no-untyped-def]
        events.append("stop")
        return GuardStatus(
            alive=True,
            supervisor="systemd",
            pid="4242",
            detail="guard still reported alive after stop",
        )

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", respawned)

    response = client.post(f"/targets/{tid}/guard/stop")

    assert response.status_code == 200
    assert response.json()["alive"] is True
    assert response.json()["pid"] == "4242"
    assert "still reported alive" in response.json()["detail"]
    assert events == [f"lookup:{tid}", "revoke:agent-stable", "stop"]


def test_guard_stop_busy_target_returns_409_without_side_effects(
    client, monkeypatch: pytest.MonkeyPatch
):
    tid = _register_ssh(client)
    events: list[str] = []
    _install_identity_service(client, events)
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.stop_guard_for",
        lambda target: events.append("stop"),
    )
    repository = client.app.state.scan_job_repository
    lease = repository.acquire_target_operation(
        tid,
        "concurrent-lifecycle-request",
        datetime.now(UTC),
        timedelta(seconds=30),
    )
    assert lease is not None

    try:
        response = client.post(f"/targets/{tid}/guard/stop")
    finally:
        repository.release_target_operation(lease)

    assert response.status_code == 409
    assert "target is busy" in response.json()["detail"]
    assert events == []


def test_guard_stop_revocation_failure_still_stops_and_releases_lease(
    client, monkeypatch: pytest.MonkeyPatch
):
    tid = _register_ssh(client)
    events: list[str] = []
    _install_identity_service(
        client,
        events,
        revocation_error=RuntimeError("identity database is read-only"),
    )

    def stop(target):  # type: ignore[no-untyped-def]
        events.append("stop")
        return GuardStatus(alive=False, supervisor="systemd", detail="stopped")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", stop)

    response = client.post(f"/targets/{tid}/guard/stop")

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert "failed to revoke Agent certificates: identity database is read-only" in detail
    assert "remote guard stopped: stopped" in detail
    assert events == [f"lookup:{tid}", "revoke:agent-stable", "stop"]
    repository = client.app.state.scan_job_repository
    lease = repository.acquire_target_operation(
        tid,
        "verify-api-finally-released",
        datetime.now(UTC),
        timedelta(seconds=30),
    )
    assert lease is not None
    repository.release_target_operation(lease)


def test_guard_stop_reports_revocation_and_remote_errors_together(
    client, monkeypatch: pytest.MonkeyPatch
):
    tid = _register_ssh(client)
    events: list[str] = []
    _install_identity_service(
        client,
        events,
        revocation_error=RuntimeError("revocation storage unavailable"),
    )

    def unreachable(target):  # type: ignore[no-untyped-def]
        events.append("stop")
        raise RuntimeError("ssh timeout")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", unreachable)

    response = client.post(f"/targets/{tid}/guard/stop")

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert "failed to revoke Agent certificates: revocation storage unavailable" in detail
    assert "failed to stop guard daemon: ssh timeout" in detail
    assert events == [f"lookup:{tid}", "revoke:agent-stable", "stop"]


def test_guard_stop_failure_returns_502(client, monkeypatch: pytest.MonkeyPatch):
    tid = _register_ssh(client)

    def boom(target):
        raise RuntimeError("ssh down")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", boom)
    res = client.post(f"/targets/{tid}/guard/stop")
    assert res.status_code == 502
    assert "failed to stop" in res.json()["detail"]
