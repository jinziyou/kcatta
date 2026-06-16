"""Access-credential management: bootstrap key lifecycle + /credentials API.

The SSH side is mocked (fake sessions / monkeypatched auth) so these run without a
real target; ``ssh-keygen``-backed tests are skipped where the binary is absent.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.deploy import bootstrap

requires_sshkeygen = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="ssh-keygen not available"
)


class _FakeClient:
    def close(self) -> None:  # paramiko SSHClient.close()
        pass


@pytest.fixture
def cfg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect managed-key storage under tmp (never touch the real ~/.config)."""
    home = tmp_path / "cfg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home))
    return home


def _seed_managed_key(address: str, port: int) -> Path:
    """Generate a real managed keypair at its deterministic path."""
    key = bootstrap.managed_key_path(address, port)
    user = address.split("@", 1)[0]
    host = address.split("@", 1)[1]
    bootstrap._generate_keypair(key, user, host)
    return key


# ---- bootstrap: fingerprint / can_authenticate -----------------------------


@requires_sshkeygen
def test_key_fingerprint_real_key(cfg_home: Path, tmp_path: Path):
    key = tmp_path / "k.ed25519"
    bootstrap._generate_keypair(key, "u", "h")
    fp = bootstrap.key_fingerprint(key)
    assert fp is not None
    assert fp.startswith("SHA256:")


def test_key_fingerprint_missing_pub(tmp_path: Path):
    assert bootstrap.key_fingerprint(tmp_path / "nope.ed25519") is None


def test_can_authenticate_missing_key_is_false(cfg_home: Path):
    # No key on disk → never claims it can authenticate (no SSH attempt).
    assert bootstrap.can_authenticate("root@10.0.0.1", 22) is False


# ---- bootstrap: rotate_key -------------------------------------------------


@requires_sshkeygen
def test_rotate_passwordless_when_old_key_works(cfg_home: Path, monkeypatch: pytest.MonkeyPatch):
    address, port = "root@10.0.0.1", 22
    key = _seed_managed_key(address, port)
    old_pub = bootstrap._pub_path(key).read_text()

    calls: list[str] = []

    def record_exec(_client, cmd):
        calls.append(cmd)
        return ("__removed", "", 0)

    monkeypatch.setattr(bootstrap, "_key_session", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(
        bootstrap, "_password_session", lambda *a, **k: pytest.fail("must not use password")
    )
    monkeypatch.setattr(bootstrap, "_key_auth_succeeds", lambda *a, **k: True)
    monkeypatch.setattr(bootstrap, "_exec", record_exec)

    result = bootstrap.rotate_key(address, port)

    assert result == key
    # The new keypair was swapped into the managed path (pub content changed).
    assert bootstrap._pub_path(key).read_text() != old_pub
    # The staged temp key was cleaned up.
    assert not key.with_name(key.name + ".new").exists()
    # Both an install (new) and a removal (old) ran over the session.
    assert any("authorized_keys" in c and "echo" in c for c in calls)
    assert len(calls) >= 2


@requires_sshkeygen
def test_rotate_uses_password_when_old_key_broken(cfg_home: Path, monkeypatch: pytest.MonkeyPatch):
    address, port = "root@10.0.0.2", 22
    _seed_managed_key(address, port)
    used = {"password": False}

    def fake_password_session(*a, **k):
        used["password"] = True
        return _FakeClient()

    monkeypatch.setattr(
        bootstrap, "_key_session", lambda *a, **k: pytest.fail("old key broken; no key auth")
    )
    monkeypatch.setattr(bootstrap, "_password_session", fake_password_session)
    # Old key fails; the freshly generated key (name endswith .new) verifies.
    monkeypatch.setattr(
        bootstrap, "_key_auth_succeeds", lambda user, host, port, k: k.name.endswith(".new")
    )
    monkeypatch.setattr(bootstrap, "_exec", lambda c, cmd: ("__removed", "", 0))

    bootstrap.rotate_key(address, port, password="pw")
    assert used["password"] is True


@requires_sshkeygen
def test_rotate_aborts_and_cleans_up_when_no_auth(cfg_home: Path, monkeypatch: pytest.MonkeyPatch):
    address, port = "root@10.0.0.3", 22
    key = _seed_managed_key(address, port)
    old_pub = bootstrap._pub_path(key).read_text()
    # Old key broken + no password → cannot install → abort without damage.
    monkeypatch.setattr(bootstrap, "_key_auth_succeeds", lambda *a, **k: False)

    with pytest.raises(RuntimeError):
        bootstrap.rotate_key(address, port, password=None)

    assert bootstrap._pub_path(key).read_text() == old_pub  # old key untouched
    assert not key.with_name(key.name + ".new").exists()  # temp cleaned


@requires_sshkeygen
def test_revoke_key_removes_line(cfg_home: Path, monkeypatch: pytest.MonkeyPatch):
    address, port = "root@10.0.0.4", 22
    _seed_managed_key(address, port)
    monkeypatch.setattr(bootstrap, "_key_auth_succeeds", lambda *a, **k: True)
    monkeypatch.setattr(bootstrap, "_key_session", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(bootstrap, "_exec", lambda c, cmd: ("__removed\n", "", 0))
    assert bootstrap.revoke_key(address, port) is True


def test_revoke_key_missing_pub_raises_clearly(cfg_home: Path):
    # Private key present, .pub absent → a clear error before any SSH (not an
    # opaque FileNotFoundError → 502).
    address, port = "root@10.0.0.5", 22
    key = bootstrap.managed_key_path(address, port)
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("PRIVATE")
    with pytest.raises(RuntimeError, match="missing"):
        bootstrap.revoke_key(address, port)


# ---- /credentials API ------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("ANALYZER_API_TOKEN", raising=False)
    with TestClient(create_app()) as c:
        yield c


def _register(client, **kw) -> dict:
    body = {"name": "t", "address": "root@10.0.0.1", "transport": "ssh", **kw}
    r = client.post("/targets", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_credentials_list_groups_shared_managed_key(client):
    # Two managed_key targets at the SAME address+port share one credential.
    _register(client, name="a", address="root@10.0.0.1")
    _register(client, name="b", address="root@10.0.0.1")
    creds = client.get("/credentials").json()
    assert len(creds) == 1
    assert creds[0]["credential_mode"] == "managed_key"
    assert len(creds[0]["target_ids"]) == 2
    # Registered without a password → no key bootstrapped → not present on disk.
    assert creds[0]["exists"] is False


def test_credentials_list_excludes_local_and_includes_identity(client):
    _register(client, name="m", address="root@10.0.0.1")
    _register(
        client,
        name="id",
        address="root@10.0.0.2",
        credential_mode="identity",
        identity_path="/keys/id_ed25519",
    )
    _register(client, name="loc", address="localhost", transport="local")
    creds = client.get("/credentials").json()
    assert sorted(c["credential_mode"] for c in creds) == ["identity", "managed_key"]


def test_identity_same_path_distinct_addresses_not_merged(client):
    # Two targets sharing one identity file but different endpoints must stay
    # distinct credentials (else test/rotate would act on only the first address).
    _register(
        client,
        name="a",
        address="root@10.0.0.1",
        credential_mode="identity",
        identity_path="/k/shared",
    )
    _register(
        client,
        name="b",
        address="admin@10.0.0.2",
        credential_mode="identity",
        identity_path="/k/shared",
    )
    creds = client.get("/credentials").json()
    assert len(creds) == 2
    assert sorted(c["address"] for c in creds) == ["admin@10.0.0.2", "root@10.0.0.1"]
    assert len({c["credential_id"] for c in creds}) == 2


def test_register_managed_requires_user_at_host(client):
    # A managed-key target with a non user@host address is rejected up front.
    r = client.post("/targets", json={"name": "bad", "address": "just-a-host", "transport": "ssh"})
    assert r.status_code == 400
    assert "user@host" in r.json()["detail"]


@requires_sshkeygen
def test_credentials_show_fingerprint_when_key_present(client):
    _register(client, name="m", address="root@10.0.0.9")
    key = bootstrap.managed_key_path("root@10.0.0.9", 22)
    bootstrap._generate_keypair(key, "root", "10.0.0.9")
    creds = client.get("/credentials").json()
    assert len(creds) == 1
    cred = creds[0]
    assert cred["exists"] is True
    assert cred["fingerprint"].startswith("SHA256:")
    cid = cred["credential_id"]
    assert client.get(f"/credentials/{cid}").json()["credential_id"] == cid
    assert client.get("/credentials/cred-nope").status_code == 404


def _seed_fake_key_on_disk(address: str, port: int) -> Path:
    key = bootstrap.managed_key_path(address, port)
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("PRIVATE")
    bootstrap._pub_path(key).write_text("ssh-ed25519 AAAAfake comment")
    return key


def test_credential_test_endpoint(client, monkeypatch: pytest.MonkeyPatch):
    _register(client, name="m", address="root@10.0.0.1")
    _seed_fake_key_on_disk("root@10.0.0.1", 22)
    cid = client.get("/credentials").json()[0]["credential_id"]
    monkeypatch.setattr("analyzer.deploy.bootstrap.can_authenticate", lambda *a, **k: True)
    body = client.post(f"/credentials/{cid}/test").json()
    assert body["ok"] is True
    assert "succeeded" in body["detail"]


def test_credential_test_missing_key_is_false(client):
    _register(client, name="m", address="root@10.0.0.1")  # no key on disk
    cid = client.get("/credentials").json()[0]["credential_id"]
    body = client.post(f"/credentials/{cid}/test").json()
    assert body["ok"] is False
    assert "missing" in body["detail"]


def test_credential_rotate_endpoint(client, monkeypatch: pytest.MonkeyPatch):
    _register(client, name="m", address="root@10.0.0.1")
    key = _seed_fake_key_on_disk("root@10.0.0.1", 22)
    cid = client.get("/credentials").json()[0]["credential_id"]
    called = {}

    def fake_rotate(address, port, password=None):
        called["address"] = address
        called["password"] = password
        return key

    monkeypatch.setattr("analyzer.deploy.bootstrap.rotate_key", fake_rotate)
    r = client.post(f"/credentials/{cid}/rotate", json={"password": "pw"})
    assert r.status_code == 200, r.text
    assert called == {"address": "root@10.0.0.1", "password": "pw"}
    assert r.json()["credential_id"] == cid


def test_rotate_rejects_identity(client):
    _register(
        client, name="id", address="root@10.0.0.2", credential_mode="identity", identity_path="/k"
    )
    cid = client.get("/credentials").json()[0]["credential_id"]
    r = client.post(f"/credentials/{cid}/rotate", json={})
    assert r.status_code == 400
    assert "managed-key" in r.json()["detail"]


def test_credential_revoke_endpoint(client, monkeypatch: pytest.MonkeyPatch):
    _register(client, name="m", address="root@10.0.0.1")
    key = _seed_fake_key_on_disk("root@10.0.0.1", 22)
    cid = client.get("/credentials").json()[0]["credential_id"]
    monkeypatch.setattr("analyzer.deploy.bootstrap.revoke_key", lambda *a, **k: True)
    body = client.post(f"/credentials/{cid}/revoke", json={}).json()
    assert body["revoked"] is True
    assert body["key_deleted"] is True
    assert not key.exists()
    assert not bootstrap._pub_path(key).exists()
    # Target still references it, so it remains listed but now absent.
    assert client.get("/credentials").json()[0]["exists"] is False


def test_revoke_missing_key_is_soft(client):
    _register(client, name="m", address="root@10.0.0.7")  # no key on disk
    cid = client.get("/credentials").json()[0]["credential_id"]
    body = client.post(f"/credentials/{cid}/revoke", json={}).json()
    assert body["revoked"] is False
    assert "already absent" in body["detail"]
