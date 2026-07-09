"""Local host scan (transport=local): run the bundled agent-collect-host in-place, no SSH.

Uses a fake `agent-collect-host` shell script (resolved through ANALYZER_AGENT_TARGET_DIR,
the same path the real bundled binary lives at) that records its argv and writes the
per-asset JSON the real binary would — so the local executor / trigger / API dispatch
/ CLI are exercised end to end without a real scan.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app, scans
from analyzer.cli import scan_main
from analyzer.deploy import local as deploy_local
from analyzer.deploy import trigger as deploy_trigger
from analyzer.deploy.agent import MalwareAgentOptions
from analyzer.schemas import (
    ScanCapability,
    ScanJob,
    ScanJobOptions,
    ScanResult,
    ScanTarget,
    Transport,
)

_TRIPLES = {"x86_64": "x86_64-unknown-linux-musl", "aarch64": "aarch64-unknown-linux-musl"}

# Fake agent-collect-host: record argv (so tests can assert flag wiring), then write the
# per-asset JSON the real binary would. Writes malware.json only when --malware is
# passed, mirroring the real binary's conditional output.
_FAKE_AGENT_HOST = """#!/bin/sh
argv="$*"
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    *) shift;;
  esac
done
mkdir -p "$out"
printf '%s' "$argv" > "$out/_argv.txt"
cat > "$out/host.json" <<'JSON'
{
  "host_id": "host-localbox",
  "hostname": "localbox",
  "os": "Ubuntu 22.04",
  "kernel": null,
  "arch": "x86_64",
  "ip_addrs": [],
  "mac_addrs": [],
  "boot_time": null
}
JSON
cat > "$out/packages.json" <<'JSON'
[
  {
    "kind": "package",
    "asset_id": "pkg-curl",
    "name": "curl",
    "version": "7.81.0",
    "source": "dpkg",
    "install_path": null,
    "ecosystem": "Ubuntu:22.04"
  }
]
JSON
case "$argv" in
  *--malware*) printf '%s' '{"scanned": 0, "findings": []}' > "$out/malware.json";;
esac
exit 0
"""


@pytest.fixture
def fake_agent_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install a fake agent-collect-host where resolve_agent_binary will find it (local arch)."""
    triple = _TRIPLES[deploy_local.local_arch()]
    target_dir = tmp_path / "agent-bins"
    binary = target_dir / triple / "release" / "agent-collect-host"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text(_FAKE_AGENT_HOST)
    binary.chmod(0o755)
    monkeypatch.setenv("ANALYZER_AGENT_TARGET_DIR", str(target_dir))
    # Don't actually walk the real root: point the scan root at an empty dir (the
    # fake ignores -r anyway, but keep it hermetic).
    monkeypatch.setenv("ANALYZER_LOCAL_SCAN_ROOT", str(tmp_path / "fakeroot"))
    (tmp_path / "fakeroot").mkdir()
    return binary


def _argv_of(out: Path) -> str:
    """The argv the fake agent-collect-host was invoked with (space-joined)."""
    return (out / "_argv.txt").read_text()


def test_transport_local_exists():
    assert Transport.LOCAL.value == "local"


def test_run_local_agent_scan_produces_files(fake_agent_host: Path, tmp_path: Path):
    out = tmp_path / "out"
    report = deploy_local.run_local_agent_scan(
        deploy_local.LocalScanOptions(output_dir=out, scan_target="host")
    )
    assert (out / "host.json").is_file()
    assert any(p.name == "host.json" for p in report.files)


def test_run_host_local_assembles_report(fake_agent_host: Path):
    # No agent_binary override + no SSH: resolves the env-installed fake, runs it,
    # assembles an AssetReport from the per-asset JSON.
    report = deploy_trigger.run_host_local(ScanJobOptions(scan_target="host", malware=False))
    assert report.host.hostname == "localbox"
    assert any(a.kind == "package" and a.name == "curl" for a in report.assets)


def test_local_scan_root_env_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ANALYZER_LOCAL_SCAN_ROOT", raising=False)
    assert deploy_local.local_scan_root() == "/"
    monkeypatch.setenv("ANALYZER_LOCAL_SCAN_ROOT", "/host")
    assert deploy_local.local_scan_root() == "/host"


def test_scan_root_default_reaches_agent_argv(fake_agent_host: Path, tmp_path: Path):
    # scan_root=None → local_scan_root() (the fixture's ANALYZER_LOCAL_SCAN_ROOT)
    # must actually reach the agent-collect-host `-r` argv.
    out = tmp_path / "out"
    deploy_local.run_local_agent_scan(deploy_local.LocalScanOptions(output_dir=out))
    fakeroot = str(tmp_path / "fakeroot")
    assert f"-r {fakeroot}" in _argv_of(out)


def test_scan_root_explicit_override_reaches_agent_argv(fake_agent_host: Path, tmp_path: Path):
    out = tmp_path / "out"
    deploy_local.run_local_agent_scan(
        deploy_local.LocalScanOptions(output_dir=out, scan_root="/custom-root")
    )
    assert "-r /custom-root" in _argv_of(out)


def test_malware_argv_and_expected_file(fake_agent_host: Path, tmp_path: Path):
    out = tmp_path / "out"
    report = deploy_local.run_local_agent_scan(
        deploy_local.LocalScanOptions(
            output_dir=out, scan_target="host", malware=MalwareAgentOptions(jobs=3)
        )
    )
    argv = _argv_of(out)
    assert "--malware" in argv
    assert "--malware-jobs 3" in argv
    # The malware.json the flag produces is collected into the report.
    assert (out / "malware.json").is_file()
    assert any(p.name == "malware.json" for p in report.files)


def test_nonzero_exit_raises(fake_agent_host: Path, tmp_path: Path):
    fake_agent_host.write_text("#!/bin/sh\necho boom >&2\nexit 3\n")
    fake_agent_host.chmod(0o755)
    with pytest.raises(RuntimeError, match="exit 3"):
        deploy_local.run_local_agent_scan(
            deploy_local.LocalScanOptions(output_dir=tmp_path / "out", scan_target="host")
        )


def test_empty_output_raises(fake_agent_host: Path, tmp_path: Path):
    # Exit 0 but produce no JSON → a clear error, not a silent empty report.
    fake_agent_host.write_text("#!/bin/sh\nexit 0\n")
    fake_agent_host.chmod(0o755)
    with pytest.raises(RuntimeError, match="no JSON"):
        deploy_local.run_local_agent_scan(
            deploy_local.LocalScanOptions(output_dir=tmp_path / "out", scan_target="host")
        )


def test_subprocess_timeout_fires(fake_agent_host: Path, tmp_path: Path):
    # A real subprocess deadline (not just the outer asyncio.wait_for) must reap a
    # slow agent-collect-host. subprocess.run raises TimeoutExpired, which run_local_agent_scan
    # lets propagate (the runner records it as a failed job).
    import subprocess

    fake_agent_host.write_text("#!/bin/sh\nsleep 5\n")
    fake_agent_host.chmod(0o755)
    with pytest.raises(subprocess.TimeoutExpired):
        deploy_local.run_local_agent_scan(
            deploy_local.LocalScanOptions(
                output_dir=tmp_path / "out", scan_target="host", timeout=0.5
            )
        )


def test_cli_local_scan_writes_asset_report(
    fake_agent_host: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # `analyzer-scan --transport local` runs without --ssh-host and assembles a report.
    out = tmp_path / "cli-out"
    monkeypatch.setattr(
        sys, "argv", ["analyzer-scan", "--transport", "local", "-t", "host", "-o", str(out)]
    )
    scan_main()
    assert (out / "host.json").is_file()
    assert (out / "asset_report.json").is_file()


def _local_target(now: datetime) -> ScanTarget:
    return ScanTarget(
        target_id="t-local",
        name="this host",
        address="localhost",
        transport=Transport.LOCAL,
        created_at=now,
    )


def test_execute_job_local_host_ingests_report(
    fake_agent_host: Path, monkeypatch: pytest.MonkeyPatch
):
    """The HOST+local happy path: run_host_local → store_asset_report → ScanResult."""
    captured: list = []
    monkeypatch.setattr(scans, "store_asset_report", lambda report, state: captured.append(report))

    now = datetime.now(UTC)
    target = _local_target(now)
    job = ScanJob(
        job_id="j-host",
        target_id="t-local",
        address="localhost",
        capability=ScanCapability.HOST,
        created_at=now,
    )
    import asyncio

    asyncio.run(scans._execute_job(state=object(), job=job, target=target, public_url=""))

    assert len(captured) == 1
    assert captured[0].host.hostname == "localbox"
    assert isinstance(job.result, ScanResult)
    assert job.result.kind == ScanCapability.HOST
    assert job.result.host_id == "host-localbox"
    assert job.result.report_id


@pytest.mark.parametrize("capability", [ScanCapability.TRACE, ScanCapability.GUARD])
def test_local_non_host_capability_is_rejected(capability: ScanCapability):
    """Local targets only support host scans; trace/guard must fail clearly."""
    import asyncio

    now = datetime.now(UTC)
    target = _local_target(now)
    job = ScanJob(
        job_id="j-1",
        target_id="t-local",
        address="localhost",
        capability=capability,
        created_at=now,
    )
    with pytest.raises(RuntimeError, match="not supported for local targets"):
        asyncio.run(scans._execute_job(state=None, job=job, target=target, public_url=""))


def test_register_local_target_no_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ANALYZER_API_TOKEN", raising=False)
    with TestClient(create_app()) as client:
        # No password needed for a local target; credential fields are normalized away.
        ok = client.post(
            "/targets",
            json={
                "name": "this host",
                "address": "localhost",
                "transport": "local",
                # A direct caller may still send SSH credential fields — they must
                # not be persisted for a local target.
                "credential_mode": "identity",
                "identity_path": "/home/analyzer/.ssh/id_ed25519",
            },
        )
        assert ok.status_code == 201, ok.text
        body = ok.json()
        assert body["transport"] == "local"
        assert body["credential_mode"] == "none"
        assert body["identity_path"] is None
        # A password is rejected for local targets.
        bad = client.post(
            "/targets",
            json={
                "name": "this host",
                "address": "localhost",
                "transport": "local",
                "password": "nope",
            },
        )
        assert bad.status_code == 400
        assert "need no credentials" in bad.json()["detail"]


def test_trigger_local_non_host_returns_400(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A trace/guard scan against a local target is rejected at trigger time (4xx),
    not silently accepted then failed by the background runner."""
    monkeypatch.setenv("ANALYZER_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ANALYZER_API_TOKEN", raising=False)
    with TestClient(create_app()) as client:
        reg = client.post(
            "/targets", json={"name": "this host", "address": "localhost", "transport": "local"}
        )
        assert reg.status_code == 201, reg.text
        target_id = reg.json()["target_id"]
        # Rejected synchronously in the request handler, before any job is created
        # (so no background scan runs here).
        for cap in ("trace", "guard"):
            res = client.post("/scans", json={"target_id": target_id, "capability": cap})
            assert res.status_code == 400, res.text
            assert "not supported for local targets" in res.json()["detail"]
