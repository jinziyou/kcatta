"""Run a registered scan target through the deploy layer and return its artifact.

Bridges the trigger API (`api/scans.py`) and the blocking SSH deploy layer. These
functions are **synchronous** (the API runs them via ``asyncio.to_thread`` so the
event loop never blocks on SSH) and return the produced envelope / result; the
caller (`api/scans.py`) is responsible for ingesting + recording the job. This
module deliberately imports nothing from `analyzer.api` — deploy stays the lower layer.

Credentials: a registered target resolves to a managed SSH key already on the
analyzer host (or a server-side identity path). Triggering needs no password.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ..schemas import (
    AssetReport,
    CredentialMode,
    ScanCapability,
    ScanJobOptions,
    ScanResult,
    ScanTarget,
    TraceBatch,
)
from . import bootstrap, winrm_bootstrap
from .agent import (
    AgentScanOptions,
    GuardDeployOptions,
    GuardStatus,
    MalwareAgentOptions,
    TraceCaptureOptions,
    guard_status,
    resolve_windows_agent_binary,
    run_agent_scan,
    run_trace_capture,
    start_guard_daemon,
    stop_guard_daemon,
)
from .local import LocalScanOptions, run_local_agent_scan
from .report import finalize_asset_report
from .winrm import WinRmAgentScanOptions, WinRmOptions, run_winrm_agent_scan

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
    with tempfile.TemporaryDirectory(prefix="analyzer-host-") as tmp:
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
    """Run the bundled agent-collect-host on the analyzer's OWN host (no SSH), assemble an AssetReport.

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
    with tempfile.TemporaryDirectory(prefix="analyzer-localhost-") as tmp:
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

    skip_cert_check mirrors the SSH AutoAddPolicy trust posture (trusted lab/intranet):
    WinRM HTTPS listeners are commonly self-signed, so server-cert validation is
    relaxed for the trigger path.
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
            "(build agent-collect-host for x86_64-pc-windows-msvc)"
        )
    with tempfile.TemporaryDirectory(prefix="analyzer-winhost-") as tmp:
        out = Path(tmp)
        run_winrm_agent_scan(
            WinRmAgentScanOptions(
                winrm=WinRmOptions.from_user_host(
                    target.address,
                    port=target.port,
                    cert_pem=cert,
                    cert_key_pem=key,
                    skip_cert_check=True,
                ),
                agent_binary=binary,
                output_dir=out,
                scan_target=options.scan_target,
            )
        )
        return finalize_asset_report(out)


def run_trace(target: ScanTarget, options: ScanJobOptions) -> TraceBatch:
    """Deploy agent-collect-trace, run one capture cycle, pull + parse the TraceBatch."""
    with tempfile.TemporaryDirectory(prefix="analyzer-flow-") as tmp:
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
        return TraceBatch.model_validate_json(trace_json.read_text(encoding="utf-8"))


def run_guard(target: ScanTarget, public_url: str, api_token: str | None = None) -> ScanResult:
    """Deploy the `agentd` binary + start `agentd guard --upload <public_url>` as a daemon.

    Returns immediately with the remote PID; the daemon keeps running and pushes
    GuardEventBatches to analyzer over time (viewable via /reports/guard-events).

    ``api_token`` is the analyzer's bearer token so the daemon's uploads pass auth
    (when enabled); it is injected into the remote daemon's environment, not its
    command line.
    """
    pid = start_guard_daemon(
        GuardDeployOptions(
            target=target.address,
            upload=public_url,
            port=target.port,
            identity=_identity_for(target),
            password=None,
            api_token=api_token,
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


def stop_guard_for(target: ScanTarget) -> GuardStatus:
    """Stop + uninstall ``target``'s resident guard daemon (no password)."""
    return stop_guard_daemon(
        GuardDeployOptions(
            target=target.address,
            upload="",  # unused for stop
            port=target.port,
            identity=_identity_for(target),
            password=None,
        )
    )
