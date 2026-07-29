"""Run a Form-registered scan target through the deploy layer and return its artifact.

Bridges Form's durable worker and the blocking SSH deploy layer. These functions
are **synchronous** (the worker runs them via ``asyncio.to_thread`` so the event
loop never blocks on SSH) and return the produced envelope/result; the worker
durably spools it, forwards it to Analyzer, and commits the fenced job state.
This module deliberately imports nothing from `analyzer.api` — deploy stays the
lower layer.

Credentials: a registered target resolves to a managed SSH key already on the
Form host (or a server-side identity path). Triggering needs no password.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from ..schemas import (
    AgentCertificateBundle,
    AssetReport,
    CredentialMode,
    ScanCapability,
    ScanJobOptions,
    ScanResult,
    ScanTarget,
    TraceBatch,
)
from ..telemetry_chunks import parse_unbounded_trace_batch
from . import bootstrap, winrm_bootstrap
from ._util import read_artifact_text, sha256_file
from .agent import (
    AgentScanOptions,
    GuardDeploymentManifest,
    GuardDeploymentProof,
    GuardDeployOptions,
    GuardStatus,
    MalwareAgentOptions,
    TraceCaptureOptions,
    guard_deployment_manifest,
    guard_deployment_proof,
    guard_identity_generation,
    guard_status,
    resolve_windows_agent_binary,
    run_agent_scan,
    run_trace_capture,
    start_guard_daemon,
    stop_guard_daemon,
)
from .agent import (
    GuardDeploymentUncertainError as GuardDeploymentUncertainError,
)
from .local import LocalScanOptions, run_local_agent_scan
from .report import finalize_asset_report
from .winrm import (
    WinRmAgentScanOptions,
    WinRmOptions,
    run_winrm_agent_scan,
    winrm_skip_cert_check,
)

# Binary selection (which musl/arch) is resolved inside the deploy layer after it
# probes the target's arch — see `agent.resolve_agent_binary`. The trigger path
# never pins a binary, so a single registered target works on x86_64 or aarch64.

_MALWARE_SIGNATURES_ENV = "FORM_MALWARE_SIGNATURES"
_MALWARE_SCAN_DEPS_ENV = "FORM_MALWARE_SCAN_DEPS"
_TRACE_INTEL_ENV = "FORM_TRACE_INTEL_PATH"
_TRACE_EBPF_ENV = "FORM_TRACE_EBPF_ENABLED"
_GUARD_INSTALL_DIR = "/var/lib/agent-guard"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be one of 1/true/yes/on or 0/false/no/off")


def _malware_options(options: ScanJobOptions) -> MalwareAgentOptions | None:
    """Resolve only server-managed malware configuration.

    The API deliberately does not accept an arbitrary filesystem path: doing so
    could copy Form host files to a registered scan target.  Operators install a
    trusted signature JSON and point ``FORM_MALWARE_SIGNATURES`` at it.
    """
    if not options.malware:
        return None
    configured = os.getenv(_MALWARE_SIGNATURES_ENV, "").strip()
    signatures = Path(configured).expanduser() if configured else None
    return MalwareAgentOptions(
        signatures=signatures,
        scan_deps=_env_flag(_MALWARE_SCAN_DEPS_ENV),
    )


def _managed_trace_intel(enabled: bool) -> Path | None:
    """Resolve the server-owned IOC corpus or fail instead of reporting a false clean pass."""
    if not enabled:
        return None
    configured = os.getenv(_TRACE_INTEL_ENV, "").strip()
    if not configured:
        raise RuntimeError(
            "IOC detection was requested but FORM_TRACE_INTEL_PATH is not configured"
        )
    path = Path(configured).expanduser()
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(
            f"IOC detection was requested but the managed feed is unavailable: {path}"
        )
    return path


def _validate_trace_ebpf_request(enabled: bool) -> None:
    if enabled and not _env_flag(_TRACE_EBPF_ENV):
        raise RuntimeError(
            "eBPF trace was requested, but FORM_TRACE_EBPF_ENABLED is false; "
            "install a matching custom Agent build and explicitly enable it"
        )


def _write_guard_config(
    directory: Path,
    target: ScanTarget,
    options: ScanJobOptions,
    *,
    intel: Path | None,
    signatures: Path | None,
) -> Path:
    """Create the monitor-only Guard profile Form deploys with its managed inputs."""
    remote_intel = f"{_GUARD_INSTALL_DIR}/trace-intel.json" if intel is not None else None
    remote_signatures = (
        f"{_GUARD_INSTALL_DIR}/malware-signatures.json" if signatures is not None else None
    )
    payload = {
        "mode": "monitor",
        "host_id": target.canonical_host_id or target.target_id,
        "fim": {"enabled": True},
        "behavior": {"enabled": True},
        "onaccess": {
            "enabled": options.guard_onaccess,
            "paths": ["/"],
            "signatures": remote_signatures,
            "signatures_sha256": sha256_file(signatures) if signatures is not None else None,
        },
        "network": {
            "enabled": options.guard_network,
            "iface": options.iface,
            "intel": remote_intel,
            "intel_sha256": sha256_file(intel) if intel is not None else None,
            "window_secs": max(1, min(int(options.duration), 5)),
        },
    }
    path = directory / "guard.json"
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    return path


def _identity_for(target: ScanTarget) -> Path | None:
    """Resolve the server-side credential for a target (no password at trigger time)."""
    if target.credential_mode == CredentialMode.IDENTITY and target.identity_path:
        return Path(target.identity_path)
    # managed_key: the key was installed at registration; reuse it by path.
    return bootstrap.managed_key_path(target.address, target.port)


def run_host(target: ScanTarget, options: ScanJobOptions) -> AssetReport:
    """Deploy agent-collect-host, pull per-asset JSON, assemble an AssetReport."""
    with tempfile.TemporaryDirectory(prefix="form-host-") as tmp:
        out = Path(tmp)
        run_agent_scan(
            AgentScanOptions(
                target=target.address,
                output_dir=out,
                scan_target=options.scan_target,
                scan_root="/",
                port=target.port,
                identity=_identity_for(target),
                password=None,
                malware=_malware_options(options),
                posture=options.posture,
                secrets=options.secrets,
            )
        )
        return finalize_asset_report(out)


def run_host_local(options: ScanJobOptions, timeout: float | None = None) -> AssetReport:
    """Run bundled agent-collect-host on the Form host (no SSH) → AssetReport.

    The local sibling of :func:`run_host` — used for ``transport=local`` targets
    (i.e. "scan the current machine"). Reuses the same per-asset JSON contract and
    report assembly; only the execution swaps from SSH-deploy to a local subprocess.

    ``timeout`` is the job's overall deadline (seconds): it is plumbed into the
    agent-collect-host subprocess (less a small margin) so the child is reaped if it
    overruns, rather than leaking past a job already flipped to FAILED.
    """
    # Fire the subprocess deadline a touch before the caller's asyncio.wait_for so
    # subprocess.run reaps the child cleanly instead of the coroutine being cancelled
    # out from under a still-running thread.
    sub_timeout = max(1.0, timeout - 5.0) if timeout else None
    with tempfile.TemporaryDirectory(prefix="form-localhost-") as tmp:
        out = Path(tmp)
        run_local_agent_scan(
            LocalScanOptions(
                output_dir=out,
                scan_target=options.scan_target,
                malware=_malware_options(options),
                posture=options.posture,
                secrets=options.secrets,
                timeout=sub_timeout,
            )
        )
        return finalize_asset_report(out)


def run_host_winrm(target: ScanTarget, options: ScanJobOptions) -> AssetReport:
    """Run agent-collect-host on a Windows target over WinRM using the managed client cert.

    The WinRM sibling of :func:`run_host` — authenticates with the bootstrapped
    client certificate (no password), runs ``agent-collect-host.exe`` against ``C:\\``,
    pulls the per-asset JSON and assembles an AssetReport via the same finalizer.

    WinRM HTTPS server certificates are validated by default. A controlled lab
    may explicitly opt out with ``FORM_WINRM_SKIP_CERT_CHECK=true``.
    """
    cert, key = winrm_bootstrap.managed_cert_paths(target.address, target.port)
    if not cert.is_file() or not key.is_file():
        raise RuntimeError(
            f"no managed WinRM client cert for {target.address}; re-register the target "
            "with a one-time password to bootstrap it"
        )
    binary = resolve_windows_agent_binary()
    if not binary.is_file():
        raise RuntimeError(
            f"Windows agent binary not found: {binary} "
            "(run make build-agent-deploy-windows or set FORM_WINDOWS_AGENT_BINARY)"
        )
    with tempfile.TemporaryDirectory(prefix="form-winhost-") as tmp:
        out = Path(tmp)
        run_winrm_agent_scan(
            WinRmAgentScanOptions(
                winrm=WinRmOptions.from_user_host(
                    target.address,
                    port=target.port,
                    cert_pem=cert,
                    cert_key_pem=key,
                    skip_cert_check=winrm_skip_cert_check(),
                ),
                agent_binary=binary,
                output_dir=out,
                scan_target=options.scan_target,
                # Windows already ships a stronger, continuously updated AV.
                # Keep Kcatta's portable signature engine for local/SSH hosts,
                # but avoid running both engines over the same Windows files.
                malware=None,
                posture=options.posture,
                secrets=options.secrets,
                defender_scan=(options.windows_defender_scan.value if options.malware else None),
            )
        )
        return finalize_asset_report(out)


def run_trace(target: ScanTarget, options: ScanJobOptions) -> TraceBatch:
    """Deploy agent-collect-trace, run one capture cycle, pull + parse the TraceBatch."""
    _validate_trace_ebpf_request(options.ebpf)
    intel = _managed_trace_intel(options.intel)
    with tempfile.TemporaryDirectory(prefix="form-trace-") as tmp:
        trace_json = run_trace_capture(
            TraceCaptureOptions(
                target=target.address,
                output_dir=Path(tmp),
                port=target.port,
                identity=_identity_for(target),
                password=None,
                pcap=options.pcap,
                iface=options.iface,
                duration=options.duration,
                bpf=options.bpf,
                intel=intel,
                ebpf=options.ebpf,
            )
        )
        return parse_unbounded_trace_batch(read_artifact_text(trace_json))


def run_guard(
    target: ScanTarget,
    public_url: str,
    api_token: str | None = None,
    certificate_bundle: AgentCertificateBundle | None = None,
    activation_callback: Callable[[], None] | None = None,
    options: ScanJobOptions | None = None,
) -> ScanResult:
    """Deploy `agentd` and start `agentd respond --upload <public_url>` as a daemon.

    Returns immediately with the remote PID; the daemon keeps running and pushes
    GuardEventBatches to Form over time (viewable via /reports/guard-events).

    ``certificate_bundle`` is the preferred per-Agent mTLS material. When it is
    present, no legacy ``FORM_INGEST_TOKEN`` is deployed even if ``api_token`` is
    also supplied. ``api_token`` remains the backward-compatible migration path.
    Neither PEM material nor tokens are placed on the remote command line.
    """
    # Direct/legacy callers that pre-date per-job Guard options retain the old
    # FIM+behavior profile. The durable worker always supplies the persisted
    # ScanJobOptions, whose explicit defaults enable managed network detection.
    resolved = options or ScanJobOptions(guard_network=False, intel=False)
    intel = _managed_trace_intel(resolved.intel) if resolved.guard_network else None
    malware = _malware_options(resolved)
    signatures = malware.signatures if malware is not None else None
    with tempfile.TemporaryDirectory(prefix="form-guard-") as tmp:
        config = _write_guard_config(
            Path(tmp), target, resolved, intel=intel, signatures=signatures
        )
        pid = start_guard_daemon(
            GuardDeployOptions(
                target=target.address,
                upload=public_url,
                install_dir=_GUARD_INSTALL_DIR,
                config=config,
                port=target.port,
                identity=_identity_for(target),
                password=None,
                api_token=api_token,
                certificate_bundle=certificate_bundle,
                activation_callback=activation_callback,
                intel=intel,
                malware_signatures=signatures,
            )
        )
    return ScanResult(
        kind=ScanCapability.GUARD,
        host_id=target.address,
        pid=pid,
        detail=f"guard daemon started (pid {pid}); events stream to {public_url}",
    )


def guard_status_for(target: ScanTarget) -> GuardStatus:
    """Probe whether ``target``'s resident guard daemon is alive (no password)."""
    return guard_status(target.address, target.port, identity=_identity_for(target))


def guard_deployment_manifest_for(target: ScanTarget) -> GuardDeploymentManifest | None:
    """Return the validated server-owned proof of a resident Guard deployment."""

    return guard_deployment_manifest(
        target.address,
        target.port,
        identity=_identity_for(target),
    )


def guard_deployment_proof_for(target: ScanTarget) -> GuardDeploymentProof:
    """Return one remote-lock-consistent Guard manifest/liveness proof."""

    return guard_deployment_proof(
        target.address,
        target.port,
        identity=_identity_for(target),
    )


def guard_identity_generation_for(target: ScanTarget) -> str | None:
    """Return the deployed identity generation for fenced worker recovery."""

    return guard_identity_generation(
        target.address,
        target.port,
        identity=_identity_for(target),
    )


def stop_guard_for(
    target: ScanTarget,
    *,
    expected_manifest: GuardDeploymentManifest | None = None,
) -> GuardStatus:
    """Stop + uninstall ``target``'s resident guard daemon (no password)."""
    options = GuardDeployOptions(
        target=target.address,
        upload="",  # unused for stop
        port=target.port,
        identity=_identity_for(target),
        password=None,
    )
    if expected_manifest is None:
        return stop_guard_daemon(options)
    return stop_guard_daemon(options, expected_manifest=expected_manifest)
