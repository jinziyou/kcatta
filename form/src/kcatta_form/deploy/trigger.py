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
from ._util import read_artifact_text
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
                malware=MalwareAgentOptions() if options.malware else None,
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
                malware=MalwareAgentOptions() if options.malware else None,
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
                malware=options.malware,
            )
        )
        return finalize_asset_report(out)


def run_trace(target: ScanTarget, options: ScanJobOptions) -> TraceBatch:
    """Deploy agent-collect-trace, run one capture cycle, pull + parse the TraceBatch."""
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
            )
        )
        return parse_unbounded_trace_batch(read_artifact_text(trace_json))


def run_guard(
    target: ScanTarget,
    public_url: str,
    api_token: str | None = None,
    certificate_bundle: AgentCertificateBundle | None = None,
    activation_callback: Callable[[], None] | None = None,
) -> ScanResult:
    """Deploy `agentd` and start `agentd respond --upload <public_url>` as a daemon.

    Returns immediately with the remote PID; the daemon keeps running and pushes
    GuardEventBatches to Form over time (viewable via /reports/guard-events).

    ``certificate_bundle`` is the preferred per-Agent mTLS material. When it is
    present, no legacy ``FORM_INGEST_TOKEN`` is deployed even if ``api_token`` is
    also supplied. ``api_token`` remains the backward-compatible migration path.
    Neither PEM material nor tokens are placed on the remote command line.
    """
    pid = start_guard_daemon(
        GuardDeployOptions(
            target=target.address,
            upload=public_url,
            port=target.port,
            identity=_identity_for(target),
            password=None,
            api_token=api_token,
            certificate_bundle=certificate_bundle,
            activation_callback=activation_callback,
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
