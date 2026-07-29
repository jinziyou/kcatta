"""Unit tests for Form's remote-scan deployment layer (no network).

Covers the pure helpers ported from the former Rust ``agent-remote`` crate and
the AssetReport assembly from pulled per-asset JSON. Imports submodules directly
so these run without the optional SSH/WinRM transports installed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kcatta_form.deploy import _util
from kcatta_form.deploy import report as deploy_report

# ---- pure helpers (shared.rs port) -----------------------------------------


def test_expected_files_per_target():
    assert _util.expected_files("host") == (
        "host.json",
        "findings.json",
        "detector-runs.json",
    )
    assert _util.expected_files("all") == (
        "host.json",
        "packages.json",
        "services.json",
        "ports.json",
        "accounts.json",
        "credentials.json",
        "containers.json",
        "images.json",
        "findings.json",
        "detector-runs.json",
    )
    assert len(_util.expected_files("all")) == len(set(_util.expected_files("all")))


def test_expected_files_rejects_unknown():
    with pytest.raises(ValueError):
        _util.expected_files("ports")


def test_form_rejects_standalone_sbom_export_with_clear_error():
    with pytest.raises(ValueError, match="standalone CycloneDX export"):
        _util.validate_scan_options("sbom", "apps")


def test_validate_scan_options_accepts_whitelisted():
    # Valid combos must not raise (these reach a remote shell).
    _util.validate_scan_options("all", "full")
    _util.validate_scan_options("host", "apps")


def test_scan_job_detector_and_trace_guard_defaults_are_explicit():
    from kcatta_form.schemas import ScanJobOptions

    options = ScanJobOptions()
    assert options.posture is True
    assert options.secrets is False
    assert options.intel is True
    assert options.ebpf is False
    assert options.guard_network is True
    assert options.guard_onaccess is False


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
        _util.sha256_file(abc) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
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


def test_finalize_merges_all_asset_kinds_and_canonical_findings(tmp_path: Path):
    _write_host(tmp_path)
    rows = {
        "ports.json": [
            {
                "kind": "port",
                "asset_id": "port-22",
                "proto": "tcp",
                "port": 22,
                "listen_addr": "0.0.0.0",
            }
        ],
        "containers.json": [
            {
                "kind": "container",
                "asset_id": "ctr-1",
                "name": "web",
                "runtime": "docker",
            }
        ],
        "images.json": [
            {
                "kind": "image",
                "asset_id": "img-1",
                "name": "web:latest",
                "runtime": "docker",
                "tags": ["web:latest"],
            }
        ],
    }
    for name, value in rows.items():
        (tmp_path / name).write_text(json.dumps(value))
    (tmp_path / "findings.json").write_text(
        json.dumps(
            [
                {
                    "vuln_id": "SSH_ROOT_LOGIN",
                    "severity": "high",
                    "affected_asset_id": "untrusted-remote-id",
                    "source": "posture",
                    "references": [],
                }
            ]
        )
    )
    (tmp_path / "detector-runs.json").write_text(
        json.dumps(
            [{"detector": "posture", "status": "complete", "finding_count": 1}]
        )
    )

    report = deploy_report.finalize_asset_report(tmp_path)
    assert {asset.kind for asset in report.assets} == {"port", "container", "image"}
    assert report.vulnerabilities[0].source == "posture"
    assert report.vulnerabilities[0].affected_asset_id == "host-demo-root"
    assert report.detector_runs is not None
    assert report.detector_runs[0].detector == "posture"
    assert report.detector_runs[0].finding_count == 1


def test_finalize_refuses_to_silently_discard_sbom(tmp_path: Path):
    _write_host(tmp_path)
    (tmp_path / "sbom.cyclonedx.json").write_text('{"bomFormat":"CycloneDX"}')
    with pytest.raises(ValueError, match="standalone export"):
        deploy_report.finalize_asset_report(tmp_path)


def test_write_asset_report_roundtrips(tmp_path: Path):
    _write_host(tmp_path)
    report = deploy_report.assemble_asset_report(tmp_path)
    path = deploy_report.write_asset_report(tmp_path, report)
    assert path.name == "asset_report.json"
    from analyzer.schemas import AssetReport

    roundtrip = AssetReport.model_validate_json(path.read_text())
    assert roundtrip.host.host_id == "host-demo-root"


# ---- trace / guard remote scheduling helpers --------------------------------


def test_parse_marked_pid():
    from kcatta_form.deploy import agent as deploy_agent

    assert deploy_agent._parse_marked_pid("noise\n__pid=4242\n") == "4242"
    assert deploy_agent._parse_marked_pid("__pid=7") == "7"
    assert deploy_agent._parse_marked_pid("no marker") == ""
    assert deploy_agent._parse_marked_pid("__pid=notanumber") == ""


def test_form_trace_backend_is_live_by_default(tmp_path: Path):
    from kcatta_form.deploy import agent as deploy_agent

    default = deploy_agent.TraceCaptureOptions(target="root@host", output_dir=tmp_path)
    assert deploy_agent._trace_capture_args(default) == " --winnet --duration 5"
    assert "mock" not in deploy_agent._trace_capture_args(default)

    pcap = deploy_agent.TraceCaptureOptions(
        target="root@host",
        output_dir=tmp_path,
        pcap=True,
        iface="eth0",
        duration=0,
        bpf="tcp port 443",
    )
    args = deploy_agent._trace_capture_args(pcap)
    assert "--pcap" in args
    assert "--duration 1" in args

    ebpf = deploy_agent.TraceCaptureOptions(
        target="root@host", output_dir=tmp_path, duration=7, ebpf=True
    )
    args = deploy_agent._trace_capture_args(ebpf)
    assert "--winnet" in args
    assert "--ebpf --ebpf-duration 7" in args


def test_managed_trace_feed_and_guard_profile_are_explicit(tmp_path: Path, monkeypatch):
    from kcatta_form.deploy import trigger as deploy_trigger
    from kcatta_form.schemas import ScanJobOptions, ScanTarget

    intel = tmp_path / "intel.json"
    signatures = tmp_path / "signatures.json"
    intel.write_text('{"source":"test","indicators":[]}\n', encoding="utf-8")
    signatures.write_text('{"sha256":{},"bytes":[]}\n', encoding="utf-8")
    monkeypatch.setenv("FORM_TRACE_INTEL_PATH", str(intel))

    assert deploy_trigger._managed_trace_intel(True) == intel
    assert deploy_trigger._managed_trace_intel(False) is None
    target = ScanTarget.model_validate(
        {
            "target_id": "target-1",
            "canonical_host_id": "stable-host-1",
            "name": "node",
            "address": "root@192.0.2.10",
            "created_at": "2026-07-15T00:00:00Z",
        }
    )
    config_path = deploy_trigger._write_guard_config(
        tmp_path,
        target,
        ScanJobOptions(guard_network=True, guard_onaccess=True),
        intel=intel,
        signatures=signatures,
    )
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["mode"] == "monitor"
    assert config["host_id"] == "stable-host-1"
    assert config["network"] == {
        "enabled": True,
        "iface": "any",
        "intel": "/var/lib/agent-guard/trace-intel.json",
        "intel_sha256": _util.sha256_file(intel),
        "window_secs": 5,
    }
    assert config["onaccess"]["enabled"] is True
    assert config["onaccess"]["paths"] == ["/"]
    assert config["onaccess"]["signatures_sha256"] == _util.sha256_file(signatures)

    monkeypatch.delenv("FORM_TRACE_INTEL_PATH")
    with pytest.raises(RuntimeError, match="FORM_TRACE_INTEL_PATH"):
        deploy_trigger._managed_trace_intel(True)


def test_ebpf_request_requires_an_explicit_custom_build_gate(monkeypatch):
    from kcatta_form.deploy import trigger as deploy_trigger

    monkeypatch.delenv("FORM_TRACE_EBPF_ENABLED", raising=False)
    with pytest.raises(RuntimeError, match="FORM_TRACE_EBPF_ENABLED"):
        deploy_trigger._validate_trace_ebpf_request(True)
    monkeypatch.setenv("FORM_TRACE_EBPF_ENABLED", "true")
    deploy_trigger._validate_trace_ebpf_request(True)


# ---- multi-arch binary resolution (x86_64 / aarch64) -----------------------


def test_resolve_agent_binary_per_arch():
    from kcatta_form.deploy import agent as deploy_agent

    x = deploy_agent.resolve_agent_binary("x86_64", "agent-collect-host", None)
    assert x.as_posix().endswith("x86_64-unknown-linux-musl/release/agent-collect-host")
    a = deploy_agent.resolve_agent_binary("aarch64", "agentd", None)
    assert a.as_posix().endswith("aarch64-unknown-linux-musl/release/agentd")
    # An explicit override wins over arch-based resolution.
    override = Path("/x/agentd")
    assert deploy_agent.resolve_agent_binary("aarch64", "agentd", override) == override


def test_resolve_windows_agent_binary_prefers_official_gnu_and_supports_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from kcatta_form.deploy import agent as deploy_agent

    monkeypatch.setenv("FORM_AGENT_TARGET_DIR", str(tmp_path))
    monkeypatch.delenv("FORM_WINDOWS_AGENT_BINARY", raising=False)
    expected = tmp_path / "x86_64-pc-windows-gnu/release/agent-collect-host.exe"
    assert deploy_agent.resolve_windows_agent_binary() == expected

    custom = tmp_path / "custom-host.exe"
    monkeypatch.setenv("FORM_WINDOWS_AGENT_BINARY", str(custom))
    assert deploy_agent.resolve_windows_agent_binary() == custom


def test_probe_arch_normalizes_and_rejects():
    from kcatta_form.deploy import agent as deploy_agent

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
