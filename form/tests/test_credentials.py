"""Form access-credential management: bootstrap lifecycle + /credentials API.

The SSH side is mocked (fake sessions / monkeypatched auth) so these run without a
real target; ``ssh-keygen``-backed tests are skipped where the binary is absent.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kcatta_form.api import create_app
from kcatta_form.deploy import bootstrap

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


def test_managed_key_paths_disambiguate_sanitize_collisions(cfg_home: Path):
    first = bootstrap.default_key_path("DOMAIN\\ops", "node/prod", 22)
    colliding_user = bootstrap.default_key_path("DOMAIN_ops", "node/prod", 22)
    colliding_host = bootstrap.default_key_path("DOMAIN\\ops", "node?prod", 22)
    other_port = bootstrap.default_key_path("DOMAIN\\ops", "node/prod", 2222)

    assert bootstrap._sanitize("DOMAIN\\ops") == bootstrap._sanitize("DOMAIN_ops")
    assert bootstrap._sanitize("node/prod") == bootstrap._sanitize("node?prod")
    assert len({first, colliding_user, colliding_host, other_port}) == 4


def test_managed_key_filename_is_bounded_for_long_unicode_endpoint(cfg_home: Path):
    path = bootstrap.default_key_path("用" * 100, ("a" * 250) + ".example", 65535)

    assert len(path.name.encode()) <= 255
    assert path.name.endswith(".ed25519")


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

    # _authed_session must fall back to the password for the old key; after the
    # staged key is promoted, rotation opens a new-key session to revoke the old line.
    monkeypatch.setattr(bootstrap, "_key_session", lambda *a, **k: _FakeClient())
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
def test_rotate_rejects_incomplete_managed_keypair(cfg_home: Path):
    address, port = "root@10.0.0.35", 22
    key = _seed_managed_key(address, port)
    bootstrap._pub_path(key).unlink()

    with pytest.raises(RuntimeError, match="keypair.*incomplete"):
        bootstrap.rotate_key(address, port, password="pw")

    assert key.exists()
    assert not key.with_name(key.name + ".new").exists()


@requires_sshkeygen
def test_rotate_verifies_new_key_before_removing_old(
    cfg_home: Path, monkeypatch: pytest.MonkeyPatch
):
    address, port = "root@10.0.0.33", 22
    key = _seed_managed_key(address, port)
    old_private = key.read_bytes()
    old_public = bootstrap._pub_path(key).read_bytes()
    commands: list[str] = []

    monkeypatch.setattr(bootstrap, "_key_session", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(bootstrap, "_key_auth_succeeds", lambda *a, **k: False)
    monkeypatch.setattr(bootstrap, "_password_session", lambda *a, **k: _FakeClient())

    def record_exec(_client, command):
        commands.append(command)
        return ("__removed", "", 0)

    monkeypatch.setattr(bootstrap, "_exec", record_exec)

    with pytest.raises(RuntimeError, match="key login still fails"):
        bootstrap.rotate_key(address, port, password="pw")

    assert key.read_bytes() == old_private
    assert bootstrap._pub_path(key).read_bytes() == old_public
    # Install-new then cleanup-new. The old line is never revoked because proof failed.
    assert len(commands) == 2
    assert old_public.decode().strip() not in commands[1]
    assert not key.with_name(key.name + ".new").exists()


@requires_sshkeygen
def test_rotate_keeps_proven_new_key_when_old_revoke_result_is_ambiguous(
    cfg_home: Path, monkeypatch: pytest.MonkeyPatch
):
    address, port = "root@10.0.0.34", 22
    key = _seed_managed_key(address, port)
    old_private = key.read_bytes()
    old_public = bootstrap._pub_path(key).read_bytes()
    calls = 0

    monkeypatch.setattr(bootstrap, "_key_session", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(bootstrap, "_key_auth_succeeds", lambda *a, **k: True)

    def fail_old_revoke(_client, _command):
        nonlocal calls
        calls += 1
        if calls == 2:
            return ("", "read-only authorized_keys", 1)
        return ("__removed", "", 0)

    monkeypatch.setattr(bootstrap, "_exec", fail_old_revoke)

    with pytest.raises(RuntimeError, match="new SSH key is active"):
        bootstrap.rotate_key(address, port)

    assert key.read_bytes() != old_private
    assert bootstrap._pub_path(key).read_bytes() != old_public
    assert key.with_name(key.name + ".rotate-old").read_bytes() == old_private
    assert (
        bootstrap._pub_path(key)
        .with_name(bootstrap._pub_path(key).name + ".rotate-old")
        .read_bytes()
        == old_public
    )
    # Install-new + attempted old cleanup only: never remove the proven new key.
    assert calls == 2


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
    monkeypatch.setenv("FORM_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("FORM_API_TOKEN", raising=False)
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


def test_managed_credential_id_is_independent_of_xdg_path(
    client, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _register(client, name="managed", address="root@10.0.0.1")
    before = client.get("/credentials").json()[0]

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "moved-config"))
    after = client.get("/credentials").json()[0]

    assert before["key_path"] != after["key_path"]
    assert before["credential_id"] == after["credential_id"]


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


def test_managed_ssh_credential_is_missing_when_public_half_is_absent(client):
    _register(client, name="half", address="root@10.0.0.19")
    key = bootstrap.managed_key_path("root@10.0.0.19", 22)
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("PRIVATE", encoding="utf-8")

    credential = client.get("/credentials").json()[0]
    assert credential["exists"] is False
    assert credential["fingerprint"] is None


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
    monkeypatch.setattr("kcatta_form.deploy.bootstrap.can_authenticate", lambda *a, **k: True)
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

    monkeypatch.setattr("kcatta_form.deploy.bootstrap.rotate_key", fake_rotate)
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
    monkeypatch.setattr("kcatta_form.deploy.bootstrap.revoke_key", lambda *a, **k: True)
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
