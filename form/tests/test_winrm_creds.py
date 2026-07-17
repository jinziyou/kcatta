"""Form WinRM client-certificate managed credential (SSH-parity bootstrap).

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

from kcatta_form.api import create_app, scans
from kcatta_form.deploy import trigger as deploy_trigger
from kcatta_form.deploy import winrm as wm
from kcatta_form.deploy import winrm_bootstrap as wb
from kcatta_form.schemas import (
    AssetReport,
    ScanCapability,
    ScanJob,
    ScanJobOptions,
    ScanResult,
    ScanTarget,
    Transport,
)

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
    other_port_cert, _ = wb.managed_cert_paths("Admin@10.0.0.50", 5987)
    assert cert.suffix == ".crt"
    assert key.suffix == ".key"
    assert cert.parent == key.parent
    assert cert != other_port_cert
    assert "-5986-" in cert.name
    assert "winrm-certs" in str(cert)
    assert str(cfg_home / "cfg") in str(cert)


def test_managed_cert_paths_disambiguate_sanitize_collision(cfg_home: Path):
    domain_user = wb.managed_cert_paths("CORP\\Admin@win01", 5986)
    underscore_user = wb.managed_cert_paths("CORP_Admin@win01", 5986)

    assert domain_user != underscore_user


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
        capture_output=True,
        text=True,
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
def test_rotate_cert_stages_then_commits_and_removes_only_old_issuer(cfg_home: Path, monkeypatch):
    target, port = "Admin@10.0.0.50", 5986
    cert, key = wb.managed_cert_paths(target, port)
    wb._generate_client_cert(cert, key, "Admin", "10.0.0.50")
    old_cert = cert.read_bytes()
    installs: list[tuple[Path, Path]] = []
    cleanup = FakeWinRmSession(_bootstrap_responses())

    def install(_target, _port, _password, staged_cert, staged_key, _skip):
        installs.append((staged_cert, staged_key))

    monkeypatch.setattr(wb, "_install_cert_auth", install)
    monkeypatch.setattr(wb, "_cert_session", lambda *args: cleanup)

    result = wb.rotate_cert(target, port, password="P@ssw0rd")

    assert result == (cert, key)
    assert cert.read_bytes() != old_cert
    assert installs[0][0].name.endswith(".new")
    cleanup_script = cleanup.scripts[-1]
    assert "$_.Subject -eq 'Admin@10.0.0.50'" in cleanup_script
    assert "$_.Issuer -eq '" in cleanup_script
    assert "$mappingLeft" in cleanup_script and "$certLeft" in cleanup_script
    assert "-ErrorAction Stop" in cleanup_script
    assert not cert.with_name(cert.name + ".rotate-old").exists()
    assert not key.with_name(key.name + ".rotate-old").exists()


@requires_openssl
def test_rotate_cert_failed_staged_login_restores_old_mapping_and_files(
    cfg_home: Path, monkeypatch
):
    target, port = "Admin@10.0.0.51", 5986
    cert, key = wb.managed_cert_paths(target, port)
    wb._generate_client_cert(cert, key, "Admin", "10.0.0.51")
    old_cert = cert.read_bytes()
    old_key = key.read_bytes()
    installs: list[tuple[Path, Path]] = []

    def fail_new_then_restore(_target, _port, _password, staged_cert, staged_key, _skip):
        installs.append((staged_cert, staged_key))
        if staged_cert.name.endswith(".new"):
            raise RuntimeError("staged certificate login failed")

    monkeypatch.setattr(wb, "_install_cert_auth", fail_new_then_restore)

    with pytest.raises(RuntimeError, match="staged certificate login failed"):
        wb.rotate_cert(target, port, password="P@ssw0rd")

    assert cert.read_bytes() == old_cert
    assert key.read_bytes() == old_key
    assert len(installs) == 2
    assert installs[1][0].name.endswith(".rotate-old")
    assert not cert.with_name(cert.name + ".new").exists()
    assert not key.with_name(key.name + ".new").exists()
    assert not cert.with_name(cert.name + ".rotate-old").exists()
    assert not key.with_name(key.name + ".rotate-old").exists()


@requires_openssl
def test_rotate_cert_keeps_recovery_copy_when_old_remote_credential_remains(
    cfg_home: Path, monkeypatch
):
    target, port = "Admin@10.0.0.52", 5986
    cert, key = wb.managed_cert_paths(target, port)
    wb._generate_client_cert(cert, key, "Admin", "10.0.0.52")
    old_cert = cert.read_bytes()
    cleanup = FakeWinRmSession(
        [
            (
                r"Get-ChildItem WSMan:\\localhost\\ClientCertificate",
                _Resp(std_out=b"", std_err=b"credential still present", status_code=1),
            )
        ]
    )
    monkeypatch.setattr(wb, "_install_cert_auth", lambda *args: None)
    monkeypatch.setattr(wb, "_cert_session", lambda *args: cleanup)

    with pytest.raises(RuntimeError, match="old mapping/certificate cleanup failed"):
        wb.rotate_cert(target, port, password="P@ssw0rd")

    assert cert.read_bytes() != old_cert  # proven new pair remains active
    assert cert.with_name(cert.name + ".rotate-old").read_bytes() == old_cert
    assert key.with_name(key.name + ".rotate-old").exists()


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


@requires_openssl
def test_revoke_cert_does_not_delete_local_pair_when_remote_postcondition_fails(
    cfg_home: Path, monkeypatch
):
    target, port = "Admin@10.0.0.53", 5986
    cert, key = wb.managed_cert_paths(target, port)
    wb._generate_client_cert(cert, key, "Admin", "10.0.0.53")
    fake = FakeWinRmSession(
        [
            (
                r"Get-ChildItem WSMan:\\localhost\\ClientCertificate",
                _Resp(std_out=b"", std_err=b"access denied", status_code=1),
            )
        ]
    )
    monkeypatch.setattr(wb, "WinRmSession", lambda opts: fake)

    with pytest.raises(RuntimeError, match="absent postcondition"):
        wb.revoke_cert(target, port)

    assert cert.exists() and key.exists()


# ---- API integration: register / trigger / credentials / execute-job -------


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("FORM_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("FORM_API_TOKEN", raising=False)
    monkeypatch.delenv(wm.WINRM_SKIP_CERT_CHECK_ENV, raising=False)
    with TestClient(create_app()) as c:
        yield c


def test_register_winrm_bootstraps_cert(client, monkeypatch: pytest.MonkeyPatch):
    called: dict = {}

    def fake_ensure(address, port, password, skip_cert_check=False):
        called.update(address=address, port=port, password=password, skip=skip_cert_check)
        return Path("x.crt"), Path("x.key")

    monkeypatch.setattr("kcatta_form.deploy.winrm_bootstrap.ensure_cert_auth", fake_ensure)
    r = client.post(
        "/targets",
        json={
            "name": "win",
            "address": "Admin@10.0.0.50",
            "transport": "winrm",
            "port": 5986,
            "password": "P@ss",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["transport"] == "winrm"
    assert body["credential_mode"] == "managed_key"
    assert called == {
        "address": "Admin@10.0.0.50",
        "port": 5986,
        "password": "P@ss",
        "skip": False,
    }


def test_register_winrm_can_explicitly_skip_certificate_validation(
    client, monkeypatch: pytest.MonkeyPatch
):
    called: dict = {}

    def fake_ensure(address, port, password, skip_cert_check=False):
        called.update(address=address, port=port, password=password, skip=skip_cert_check)
        return Path("x.crt"), Path("x.key")

    monkeypatch.setenv(wm.WINRM_SKIP_CERT_CHECK_ENV, "true")
    monkeypatch.setattr("kcatta_form.deploy.winrm_bootstrap.ensure_cert_auth", fake_ensure)
    response = client.post(
        "/targets",
        json={
            "name": "win",
            "address": "Admin@10.0.0.50",
            "transport": "winrm",
            "port": 5986,
            "password": "P@ss",
        },
    )

    assert response.status_code == 201, response.text
    assert called["skip"] is True


def test_register_winrm_rejects_identity_mode(client):
    # WinRM only supports managed (cert) creds — the API rejects identity at the boundary.
    r = client.post(
        "/targets",
        json={
            "name": "win",
            "address": "Admin@10.0.0.50",
            "transport": "winrm",
            "credential_mode": "identity",
            "identity_path": "/k",
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

    tls_checks: list[bool] = []

    def fake_can_authenticate(_address, _port, skip_cert_check=False):
        tls_checks.append(skip_cert_check)
        return True

    monkeypatch.setattr(
        "kcatta_form.deploy.winrm_bootstrap.can_authenticate_cert", fake_can_authenticate
    )
    assert client.post(f"/credentials/{cid}/test").json()["ok"] is True
    # WinRM rotation requires a password (no key-reuse path).
    assert client.post(f"/credentials/{cid}/rotate", json={}).status_code == 400

    def fake_rotate(_address, _port, _password, skip_cert_check=False):
        tls_checks.append(skip_cert_check)
        return cert, key

    monkeypatch.setattr("kcatta_form.deploy.winrm_bootstrap.rotate_cert", fake_rotate)
    assert client.post(f"/credentials/{cid}/rotate", json={"password": "pw"}).status_code == 200

    def fake_revoke(_address, _port, _password, skip_cert_check=False):
        tls_checks.append(skip_cert_check)
        return True

    monkeypatch.setattr("kcatta_form.deploy.winrm_bootstrap.revoke_cert", fake_revoke)
    revoked = client.post(f"/credentials/{cid}/revoke", json={"password": "pw"}).json()
    assert revoked["revoked"] is True
    assert tls_checks == [False, False, False]


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
    class RecordingAnalyzer:
        reports: list = []

        async def ingest_asset_report(self, report):
            self.reports.append(report)

    report = AssetReport.model_validate(
        {
            "report_id": "r-win",
            "collected_at": datetime.now(UTC).isoformat(),
            "scanner_version": "test",
            "host": {"host_id": "host-win", "hostname": "win", "os": "Windows"},
            "assets": [],
            "vulnerabilities": [],
        }
    )
    monkeypatch.setattr(deploy_trigger, "run_host_winrm", lambda target, opts: report)

    now = datetime.now(UTC)
    target = ScanTarget(
        target_id="t",
        name="win",
        address="Admin@10.0.0.50",
        port=5986,
        transport=Transport.WINRM,
        created_at=now,
    )
    job = ScanJob(
        job_id="j",
        target_id="t",
        address="Admin@10.0.0.50",
        capability=ScanCapability.HOST,
        created_at=now,
    )
    analyzer = RecordingAnalyzer()
    asyncio.run(
        scans._execute_job(
            state=object(),
            job=job,
            target=target,
            public_url="",
            analyzer_client=analyzer,
        )
    )

    assert len(analyzer.reports) == 1
    assert isinstance(job.result, ScanResult)
    assert job.result.kind == ScanCapability.HOST
    assert job.result.report_id == "r-win"
    assert analyzer.reports[0].host.host_id == "t"
    assert job.result.host_id == "t"


@pytest.mark.parametrize(("setting", "expected"), [(None, False), ("true", True)])
def test_run_host_winrm_uses_tls_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, setting, expected
):
    if setting is None:
        monkeypatch.delenv(wm.WINRM_SKIP_CERT_CHECK_ENV, raising=False)
    else:
        monkeypatch.setenv(wm.WINRM_SKIP_CERT_CHECK_ENV, setting)

    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    binary = tmp_path / "agent-collect-host.exe"
    for path in (cert, key, binary):
        path.write_bytes(b"x")

    captured: dict = {}
    monkeypatch.setattr(wb, "managed_cert_paths", lambda *_a: (cert, key))
    monkeypatch.setattr(deploy_trigger, "resolve_windows_agent_binary", lambda: binary)
    monkeypatch.setattr(
        deploy_trigger,
        "run_winrm_agent_scan",
        lambda options: captured.update(
            skip=options.winrm.skip_cert_check,
            malware=options.malware,
            defender_scan=options.defender_scan,
        ),
    )
    sentinel = object()
    monkeypatch.setattr(deploy_trigger, "finalize_asset_report", lambda _out: sentinel)
    target = ScanTarget(
        target_id="target-win",
        name="win",
        address="Admin@10.0.0.50",
        port=5986,
        transport=Transport.WINRM,
        created_at=datetime.now(UTC),
    )

    assert deploy_trigger.run_host_winrm(target, ScanJobOptions()) is sentinel
    assert captured["skip"] is expected
    assert captured["malware"] is None
    assert captured["defender_scan"] == "quick"
