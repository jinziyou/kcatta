"""Persistent SSH host-key policy shared by scans and credential bootstrap."""

from __future__ import annotations

import stat
import time
from pathlib import Path

import paramiko
import pytest

from kcatta_form.deploy import bootstrap
from kcatta_form.deploy import ssh as ssh_transport


@pytest.fixture(autouse=True)
def isolated_known_hosts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv(ssh_transport.KNOWN_HOSTS_ENV, raising=False)
    monkeypatch.delenv(ssh_transport.HOST_KEY_POLICY_ENV, raising=False)
    return ssh_transport.known_hosts_path()


def _policy(client: paramiko.SSHClient) -> paramiko.MissingHostKeyPolicy:
    return client._policy  # type: ignore[attr-defined]  # test the configured Paramiko policy


def test_accept_new_persists_first_key_and_reloads_it(isolated_known_hosts: Path):
    key = paramiko.RSAKey.generate(1024)
    client = ssh_transport.create_ssh_client()

    assert isinstance(_policy(client), ssh_transport.AcceptNewHostKeyPolicy)
    _policy(client).missing_host_key(client, "host.example", key)

    assert isolated_known_hosts.is_file()
    assert stat.S_IMODE(isolated_known_hosts.stat().st_mode) == 0o600
    reloaded = ssh_transport.create_ssh_client()
    assert reloaded.get_host_keys().check("host.example", key)


def test_accept_new_rejects_changed_key_and_preserves_pin(isolated_known_hosts: Path):
    original = paramiko.RSAKey.generate(1024)
    changed = paramiko.RSAKey.generate(1024)
    first = ssh_transport.create_ssh_client()
    _policy(first).missing_host_key(first, "host.example", original)

    # Simulate a client whose handshake began before another worker persisted the
    # key. The policy reloads under its write lock and must reject the changed key.
    stale = paramiko.SSHClient()
    policy = ssh_transport.AcceptNewHostKeyPolicy(isolated_known_hosts)
    with pytest.raises(paramiko.BadHostKeyException):
        policy.missing_host_key(stale, "host.example", changed)

    persisted = paramiko.HostKeys(str(isolated_known_hosts))
    assert persisted.check("host.example", original)
    assert not persisted.check("host.example", changed)


def test_strict_rejects_unknown_host(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ssh_transport.HOST_KEY_POLICY_ENV, "strict")
    client = ssh_transport.create_ssh_client()
    assert isinstance(_policy(client), paramiko.RejectPolicy)

    class _LoggingTransport:
        def _log(self, _level, _message) -> None:  # type: ignore[no-untyped-def]
            pass

    # RejectPolicy logs through the active transport before raising.
    client._transport = _LoggingTransport()  # type: ignore[assignment]

    with pytest.raises(paramiko.SSHException, match="not found in known_hosts"):
        _policy(client).missing_host_key(client, "unknown.example", paramiko.RSAKey.generate(1024))


def test_strict_loads_preprovisioned_host(monkeypatch: pytest.MonkeyPatch):
    key = paramiko.RSAKey.generate(1024)
    accept_new = ssh_transport.create_ssh_client()
    _policy(accept_new).missing_host_key(accept_new, "pinned.example", key)

    monkeypatch.setenv(ssh_transport.HOST_KEY_POLICY_ENV, "strict")
    strict = ssh_transport.create_ssh_client()
    assert strict.get_host_keys().check("pinned.example", key)
    assert isinstance(_policy(strict), paramiko.RejectPolicy)


def test_known_hosts_path_and_policy_are_configurable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    custom = tmp_path / "ssh" / "pinned_hosts"
    monkeypatch.setenv(ssh_transport.KNOWN_HOSTS_ENV, str(custom))
    monkeypatch.setenv(ssh_transport.HOST_KEY_POLICY_ENV, "STRICT")

    client = ssh_transport.create_ssh_client()
    assert custom.is_file()
    assert ssh_transport.known_hosts_path() == custom
    assert isinstance(_policy(client), paramiko.RejectPolicy)


def test_preexisting_known_hosts_permissions_are_tightened(
    isolated_known_hosts: Path,
):
    isolated_known_hosts.parent.mkdir(parents=True)
    isolated_known_hosts.write_text("", encoding="utf-8")
    isolated_known_hosts.chmod(0o666)

    ssh_transport.create_ssh_client()

    assert stat.S_IMODE(isolated_known_hosts.stat().st_mode) == 0o600
    assert stat.S_IMODE(isolated_known_hosts.parent.stat().st_mode) == 0o700


def test_known_hosts_symlink_is_rejected(isolated_known_hosts: Path, tmp_path: Path):
    target = tmp_path / "attacker-controlled"
    target.write_text("", encoding="utf-8")
    isolated_known_hosts.parent.mkdir(parents=True)
    isolated_known_hosts.symlink_to(target)

    with pytest.raises(ValueError, match="symlink"):
        ssh_transport.create_ssh_client()


def test_invalid_host_key_policy_fails_closed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ssh_transport.HOST_KEY_POLICY_ENV, "no-check")
    with pytest.raises(ValueError, match=ssh_transport.HOST_KEY_POLICY_ENV):
        ssh_transport.create_ssh_client()


class _FakeClient:
    def __init__(self) -> None:
        self.connect_calls: list[dict] = []
        self.sftp = _FakeSftp()
        self.closed = False

    def connect(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        self.connect_calls.append(kwargs)

    def close(self) -> None:
        self.closed = True

    def open_sftp(self):  # type: ignore[no-untyped-def]
        return self.sftp


class _FakeChannel:
    def __init__(self) -> None:
        self.timeout: float | None = None

    def settimeout(self, value: float) -> None:
        self.timeout = value


class _FakeSftp:
    def __init__(self) -> None:
        self.channel = _FakeChannel()

    def get_channel(self) -> _FakeChannel:
        return self.channel

    def close(self) -> None:
        pass


def test_scan_and_bootstrap_clients_share_factory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    scan_client = _FakeClient()
    monkeypatch.setattr(ssh_transport, "create_ssh_client", lambda: scan_client)
    session = ssh_transport.SshSession("host", "user", tmp_path / "id", port=2222)
    assert session._client is scan_client
    assert scan_client.connect_calls[0]["port"] == 2222
    assert scan_client.connect_calls[0]["channel_timeout"] == session.command_timeout
    assert session._sftp_client() is scan_client.sftp  # type: ignore[comparison-overlap]
    assert scan_client.sftp.channel.timeout == session.command_timeout

    bootstrap_client = _FakeClient()
    monkeypatch.setattr(bootstrap, "create_ssh_client", lambda: bootstrap_client)
    result = bootstrap._password_session("user", "host", 22, password="one-time")
    assert result is bootstrap_client
    assert bootstrap_client.connect_calls[0]["password"] == "one-time"


def test_ssh_operation_timeout_is_total_wall_clock_not_only_inactivity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _FakeClient()
    monkeypatch.setattr(ssh_transport, "create_ssh_client", lambda: client)
    session = ssh_transport.SshSession(
        "host",
        "user",
        tmp_path / "id",
        command_timeout=0.02,
    )

    with (
        pytest.raises(TimeoutError, match="exceeded"),
        session._bounded_operation("test transfer"),
    ):
        time.sleep(0.05)

    assert client.closed is True
