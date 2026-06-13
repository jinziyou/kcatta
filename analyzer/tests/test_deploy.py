"""Unit tests for analyzer's remote-scan deployment layer (no network).

Covers the pure helpers ported from the former Rust ``agent-remote`` crate and
the AssetReport assembly from pulled per-asset JSON. Imports submodules directly
so these run without the optional SSH/WinRM transports installed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzer.deploy import _util
from analyzer.deploy import report as deploy_report

# ---- pure helpers (shared.rs port) -----------------------------------------


def test_expected_files_per_target():
    assert _util.expected_files("host") == ("host.json",)
    assert _util.expected_files("packages") == ("packages.json",)
    assert _util.expected_files("sbom") == ("sbom.cyclonedx.json",)
    assert _util.expected_files("identity") == (
        "services.json",
        "accounts.json",
        "credentials.json",
    )
    assert len(_util.expected_files("all")) == 6


def test_expected_files_rejects_unknown():
    with pytest.raises(ValueError):
        _util.expected_files("ports")


def test_validate_scan_options_accepts_whitelisted():
    # Valid combos must not raise (these reach a remote shell).
    _util.validate_scan_options("all", "full")
    _util.validate_scan_options("host", "apps")


@pytest.mark.parametrize(
    ("target", "profile"),
    [
        ("host; touch /tmp/pwned", "apps"),  # command injection via -t
        ("all", "apps; rm -rf /"),  # injection via --windows-packages
        ("definitely-not-a-target", "apps"),
        ("all", "neither-full-nor-apps"),
    ],
)
def test_validate_scan_options_rejects_injection_and_unknown(target, profile):
    # Regression: scan_target / windows_packages were interpolated unquoted into
    # the remote command; they must be whitelist-validated BEFORE any exec.
    with pytest.raises(ValueError):
        _util.validate_scan_options(target, profile)


def test_parse_marked_exit_reads_last_marker():
    assert _util.parse_marked_exit("noise\n__exit=0\n") == 0
    assert _util.parse_marked_exit("__exit=5") == 5
    assert _util.parse_marked_exit("no marker") is None


def test_sha256_file_known_vector(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    assert (
        _util.sha256_file(empty)
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    abc = tmp_path / "abc"
    abc.write_bytes(b"abc")
    assert (
        _util.sha256_file(abc)
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sh_quote_escapes_quotes():
    assert _util.sh_quote("/tmp/x") == "/tmp/x"
    assert _util.sh_quote("a'b") == "'a'\"'\"'b'"
    assert _util.sh_quote("") == "''"


def test_split_user_host():
    assert _util.split_user_host("root@10.0.0.1") == ("root", "10.0.0.1")
    for bad in ("no-at", "@host", "user@"):
        with pytest.raises(ValueError):
            _util.split_user_host(bad)


# ---- AssetReport assembly (report.rs port) ---------------------------------


def _write_host(directory: Path) -> None:
    (directory / "host.json").write_text(
        json.dumps(
            {
                "host_id": "host-demo-root",
                "hostname": "demo",
                "os": "Ubuntu 22.04",
                "kernel": None,
                "arch": "x86_64",
                "ip_addrs": [],
                "mac_addrs": [],
                "boot_time": None,
            }
        )
    )


def test_assembles_host_and_packages(tmp_path: Path):
    _write_host(tmp_path)
    (tmp_path / "packages.json").write_text(
        json.dumps(
            [
                {
                    "kind": "package",
                    "asset_id": "pkg-openssl",
                    "name": "openssl",
                    "version": "3.0.2",
                    "source": "dpkg",
                    "install_path": None,
                    "ecosystem": "Ubuntu:22.04",
                }
            ]
        )
    )

    report = deploy_report.assemble_asset_report(tmp_path)
    assert report.host.hostname == "demo"
    assert len(report.assets) == 1
    assert report.assets[0].name == "openssl"
    assert report.vulnerabilities == []


def test_missing_host_json_is_error(tmp_path: Path):
    (tmp_path / "packages.json").write_text("[]")
    with pytest.raises(FileNotFoundError):
        deploy_report.assemble_asset_report(tmp_path)


def test_finalize_merges_malware_and_rebinds_host(tmp_path: Path):
    _write_host(tmp_path)
    (tmp_path / "malware.json").write_text(
        json.dumps(
            [
                {
                    "vuln_id": "Eicar-Test-Signature",
                    "severity": "critical",
                    "cvss_score": None,
                    "affected_asset_id": "/tmp/eicar",
                    "source": "clamav",
                    "evidence": "infected file: /tmp/eicar",
                    "references": [],
                }
            ]
        )
    )

    report = deploy_report.finalize_asset_report(tmp_path)
    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].vuln_id == "Eicar-Test-Signature"
    # affected_asset_id is rebound from the infected path to the host id.
    assert report.vulnerabilities[0].affected_asset_id == "host-demo-root"


def test_write_asset_report_roundtrips(tmp_path: Path):
    _write_host(tmp_path)
    report = deploy_report.assemble_asset_report(tmp_path)
    path = deploy_report.write_asset_report(tmp_path, report)
    assert path.name == "asset_report.json"
    from analyzer.schemas import AssetReport

    roundtrip = AssetReport.model_validate_json(path.read_text())
    assert roundtrip.host.host_id == "host-demo-root"


# ---- flow / guard remote scheduling helpers --------------------------------


def test_parse_marked_pid():
    from analyzer.deploy import agent as deploy_agent

    assert deploy_agent._parse_marked_pid("noise\n__pid=4242\n") == "4242"
    assert deploy_agent._parse_marked_pid("__pid=7") == "7"
    assert deploy_agent._parse_marked_pid("no marker") == ""
    assert deploy_agent._parse_marked_pid("__pid=notanumber") == ""


# ---- multi-arch binary resolution (x86_64 / aarch64) -----------------------


def test_resolve_agent_binary_per_arch():
    from analyzer.deploy import agent as deploy_agent

    x = deploy_agent.resolve_agent_binary("x86_64", "agent-host", None)
    assert x.as_posix().endswith("x86_64-unknown-linux-musl/release/agent-host")
    a = deploy_agent.resolve_agent_binary("aarch64", "agent", None)
    assert a.as_posix().endswith("aarch64-unknown-linux-musl/release/agent")
    # An explicit override wins over arch-based resolution.
    override = Path("/x/agent")
    assert deploy_agent.resolve_agent_binary("aarch64", "agent", override) == override


def test_probe_arch_normalizes_and_rejects():
    from analyzer.deploy import agent as deploy_agent

    class _FakeSession:
        def __init__(self, uname: str) -> None:
            self._uname = uname

        def exec(self, _cmd: str):
            return type("R", (), {"stdout": self._uname})()

    assert deploy_agent._probe_arch(_FakeSession("x86_64")) == "x86_64"
    assert deploy_agent._probe_arch(_FakeSession("amd64")) == "x86_64"
    assert deploy_agent._probe_arch(_FakeSession("aarch64\n")) == "aarch64"
    assert deploy_agent._probe_arch(_FakeSession("arm64")) == "aarch64"
    with pytest.raises(RuntimeError):
        deploy_agent._probe_arch(_FakeSession("riscv64"))
