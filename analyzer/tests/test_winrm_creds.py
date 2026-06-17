"""WinRM client-certificate managed credential (the SSH-parity bootstrap).

openssl is real (cert gen / fingerprints); the WinRM session is mocked, so the
emitted PowerShell is asserted without a live Windows target.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app, scans
from analyzer.deploy import trigger as deploy_trigger
from analyzer.deploy import winrm_bootstrap as wb
from analyzer.schemas import ScanCapability, ScanJob, ScanResult, ScanTarget, Transport

requires_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl not available"
)


class _Resp:
    def __init__(self, std_out: bytes = b"", std_err: bytes = b"", status_code: int = 0) -> None:
        self.std_out = std_out
        self.std_err = std_err
        self.status_code = status_code


class FakeWinRmSession:
    """Records run_ps scripts; serves scripted responses by regex (no pywinrm)."""

    def __init__(self, responses: list[tuple[str, _Resp]] | None = None) -> None:
        self.responses = responses or []
        self.scripts: list[str] = []
        self.host = "win-host"

    def exec(self, ps_script: str) -> _Resp:
        self.scripts.append(ps_script)
        for pattern, resp in self.responses:
            if re.search(pattern, ps_script):
                return resp
        return _Resp(std_out=b"__ok\n")

    def upload_file(self, local: Path, remote: str) -> None:
        self.scripts.append(f"<upload {local} -> {remote}>")


@pytest.fixture
def cfg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    return tmp_path


def _bootstrap_responses() -> list[tuple[str, _Resp]]:
    return [
        (r"Listener", _Resp(std_out=b"__https_ok\n")),
        (r"Import-Certificate", _Resp(std_out=b"__thumb=ABCDEF0123\n")),
        (r"New-Item -Path WSMan:\\localhost\\ClientCertificate", _Resp(std_out=b"__mapped\n")),
        (r"Get-ChildItem WSMan:\\localhost\\ClientCertificate", _Resp(std_out=b"__revoked\n")),
    ]


# ---- paths / identity validation -------------------------------------------


def test_managed_cert_paths_deterministic_under_xdg(cfg_home: Path):
    cert, key = wb.managed_cert_paths("Admin@10.0.0.50", 5986)
    assert cert.suffix == ".crt"
    assert key.suffix == ".key"
    assert cert.parent == key.parent
    assert "winrm-certs" in str(cert)
    assert str(cfg_home / "cfg") in str(cert)


@pytest.mark.parametrize("bad", ["a b@h", "u@h;rm", "u@h$(x)", "u@h'q"])
def test_identity_rejects_injection_chars(bad: str):
    with pytest.raises(ValueError):
        wb._split(bad)


def test_identity_allows_domain_backslash_user():
    assert wb._split("CORP\\Admin@win01") == ("CORP\\Admin", "win01")


# ---- cert generation / fingerprints (real openssl) -------------------------


@requires_openssl
def test_generate_client_cert_and_fingerprints(cfg_home: Path):
    cert, key = wb.managed_cert_paths("Admin@10.0.0.50", 5986)
    wb._generate_client_cert(cert, key, "Admin", "10.0.0.50")
    assert cert.exists() and key.exists()
    fp = wb.cert_fingerprint(cert)
    assert fp and fp.startswith("SHA256:")
    thumb = wb.cert_thumbprint(cert)
    assert thumb and re.fullmatch(r"[0-9A-F]+", thumb)  # uppercase hex, no separators
    # The UPN must be embedded as an msUPN otherName SAN (what the mapping matches).
    import subprocess

    txt = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-text"],
        capture_output=True, text=True,
    ).stdout
    assert "Admin@10.0.0.50" in txt
    assert "TLS Web Client Authentication" in txt


def test_cert_fingerprint_missing_returns_none(cfg_home: Path):
    cert, _ = wb.managed_cert_paths("Admin@10.0.0.50", 5986)
    assert wb.cert_fingerprint(cert) is None


# ---- ensure_cert_auth (mocked session) -------------------------------------


@requires_openssl
def test_ensure_cert_auth_emits_expected_powershell(cfg_home: Path, monkeypatch):
    fake = FakeWinRmSession(_bootstrap_responses())
    monkeypatch.setattr(wb, "WinRmSession", lambda opts: fake)

    cert, key = wb.ensure_cert_auth("Admin@10.0.0.50", 5986, "P@ssw0rd")
    assert cert.exists() and key.exists()

    joined = "\n".join(fake.scripts)
    assert "WSMan:\\localhost\\Service\\Auth\\Certificate" in joined  # enabled cert auth
    assert "Import-Certificate" in joined  # imported the cert
    assert "WSMan:\\localhost\\ClientCertificate" in joined  # created mapping
    assert "-Subject 'Admin@10.0.0.50'" in joined  # mapped on the UPN
    assert any(s.startswith("<upload") for s in fake.scripts)  # uploaded the cert


@requires_openssl
def test_ensure_cert_auth_requires_https_listener(cfg_home: Path, monkeypatch):
    fake = FakeWinRmSession([(r"Listener", _Resp(std_out=b"__no_https\n"))])
    monkeypatch.setattr(wb, "WinRmSession", lambda opts: fake)
    with pytest.raises(RuntimeError, match="HTTPS WinRM listener"):
        wb.ensure_cert_auth("Admin@10.0.0.50", 5986, "P@ssw0rd")


def test_can_authenticate_cert_false_without_files(cfg_home: Path):
    assert wb.can_authenticate_cert("Admin@10.0.0.50", 5986) is False


# ---- rotate / revoke -------------------------------------------------------


def test_rotate_cert_requires_password(cfg_home: Path):
    with pytest.raises(RuntimeError, match="requires the target account password"):
        wb.rotate_cert("Admin@10.0.0.50", 5986, password=None)


@requires_openssl
def test_revoke_cert_removes_mapping_and_local_files(cfg_home: Path, monkeypatch):
    cert, key = wb.managed_cert_paths("Admin@10.0.0.50", 5986)
    wb._generate_client_cert(cert, key, "Admin", "10.0.0.50")
    fake = FakeWinRmSession(_bootstrap_responses())
    monkeypatch.setattr(wb, "WinRmSession", lambda opts: fake)

    assert wb.revoke_cert("Admin@10.0.0.50", 5986) is True
    assert not cert.exists() and not key.exists()
    joined = "\n".join(fake.scripts)
    assert "Remove-Item" in joined
    assert "WSMan:\\localhost\\ClientCertificate" in joined


# ---- API integration: register / trigger / credentials / execute-job -------


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("ANALYZER_API_TOKEN", raising=False)
    with TestClient(create_app()) as c:
        yield c


def test_register_winrm_bootstraps_cert(client, monkeypatch: pytest.MonkeyPatch):
    called: dict = {}

    def fake_ensure(address, port, password, skip_cert_check=False):
        called.update(address=address, port=port, password=password, skip=skip_cert_check)
        return Path("x.crt"), Path("x.key")

    monkeypatch.setattr("analyzer.deploy.winrm_bootstrap.ensure_cert_auth", fake_ensure)
    r = client.post(
        "/targets",
        json={
            "name": "win", "address": "Admin@10.0.0.50", "transport": "winrm",
            "port": 5986, "password": "P@ss",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["transport"] == "winrm"
    assert body["credential_mode"] == "managed_key"
    # The bootstrap (password-bearing) session uses the same relaxed TLS posture as
    # rotate/revoke — consistent, not validate-here-skip-there.
    assert called == {"address": "Admin@10.0.0.50", "port": 5986, "password": "P@ss", "skip": True}


def test_register_winrm_rejects_identity_mode(client):
    # WinRM only supports managed (cert) creds — the API rejects identity at the boundary.
    r = client.post(
        "/targets",
        json={
            "name": "win", "address": "Admin@10.0.0.50", "transport": "winrm",
            "credential_mode": "identity", "identity_path": "/k",
        },
    )
    assert r.status_code == 400
    assert "managed-key" in r.json()["detail"]


def test_trigger_winrm_trace_returns_400(client):
    # winrm target registered without a password (no bootstrap); trace is host-only.
    reg = client.post(
        "/targets",
        json={"name": "win", "address": "Admin@10.0.0.50", "transport": "winrm", "port": 5986},
    )
    tid = reg.json()["target_id"]
    res = client.post("/scans", json={"target_id": tid, "capability": "trace"})
    assert res.status_code == 400
    assert "winrm" in res.json()["detail"]


@requires_openssl
def test_credentials_winrm_transport_and_dispatch(client, monkeypatch: pytest.MonkeyPatch):
    client.post(
        "/targets",
        json={"name": "win", "address": "Admin@10.0.0.50", "transport": "winrm", "port": 5986},
    )
    cert, key = wb.managed_cert_paths("Admin@10.0.0.50", 5986)
    wb._generate_client_cert(cert, key, "Admin", "10.0.0.50")

    creds = client.get("/credentials").json()
    assert len(creds) == 1
    c = creds[0]
    assert c["transport"] == "winrm"
    assert c["credential_mode"] == "managed_key"
    assert c["exists"] is True
    assert c["fingerprint"].startswith("SHA256:")
    cid = c["credential_id"]

    monkeypatch.setattr(
        "analyzer.deploy.winrm_bootstrap.can_authenticate_cert", lambda *a, **k: True
    )
    assert client.post(f"/credentials/{cid}/test").json()["ok"] is True
    # WinRM rotation requires a password (no key-reuse path).
    assert client.post(f"/credentials/{cid}/rotate", json={}).status_code == 400
    monkeypatch.setattr("analyzer.deploy.winrm_bootstrap.rotate_cert", lambda *a, **k: (cert, key))
    assert client.post(f"/credentials/{cid}/rotate", json={"password": "pw"}).status_code == 200
    monkeypatch.setattr("analyzer.deploy.winrm_bootstrap.revoke_cert", lambda *a, **k: True)
    revoked = client.post(f"/credentials/{cid}/revoke", json={"password": "pw"}).json()
    assert revoked["revoked"] is True


@requires_openssl
def test_winrm_cred_half_present_reports_missing(client):
    # cert present but private key gone → cert auth would fail → must report missing.
    client.post(
        "/targets",
        json={"name": "win", "address": "Admin@10.0.0.50", "transport": "winrm", "port": 5986},
    )
    cert, key = wb.managed_cert_paths("Admin@10.0.0.50", 5986)
    wb._generate_client_cert(cert, key, "Admin", "10.0.0.50")
    key.unlink()
    assert client.get("/credentials").json()[0]["exists"] is False


def test_execute_job_winrm_host_ingests(monkeypatch: pytest.MonkeyPatch):
    captured: list = []
    monkeypatch.setattr(scans, "store_asset_report", lambda report, state: captured.append(report))

    class _Host:
        host_id = "host-win"

    class _Report:
        report_id = "r-win"
        host = _Host()

    monkeypatch.setattr(deploy_trigger, "run_host_winrm", lambda target, opts: _Report())

    now = datetime.now(UTC)
    target = ScanTarget(
        target_id="t", name="win", address="Admin@10.0.0.50", port=5986,
        transport=Transport.WINRM, created_at=now,
    )
    job = ScanJob(
        job_id="j", target_id="t", address="Admin@10.0.0.50",
        capability=ScanCapability.HOST, created_at=now,
    )
    asyncio.run(scans._execute_job(state=object(), job=job, target=target, public_url=""))

    assert len(captured) == 1
    assert isinstance(job.result, ScanResult)
    assert job.result.kind == ScanCapability.HOST
    assert job.result.report_id == "r-win"
    assert job.result.host_id == "host-win"
