"""Run a registered scan target through the deploy layer and return its artifact.

Bridges the trigger API (`api/scans.py`) and the blocking SSH deploy layer. These
functions are **synchronous** (the API runs them via ``asyncio.to_thread`` so the
event loop never blocks on SSH) and return the produced envelope / result; the
caller (`api/scans.py`) is responsible for ingesting + recording the job. This
module deliberately imports nothing from `fusion.api` — deploy stays the lower layer.

Credentials: a registered target resolves to a managed SSH key already on the
fusion host (or a server-side identity path). Triggering needs no password.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ..schemas import (
    AssetReport,
    CredentialMode,
    FlowBatch,
    ScanCapability,
    ScanJobOptions,
    ScanResult,
    ScanTarget,
)
from . import bootstrap
from .agent import (
    AgentScanOptions,
    FlowCaptureOptions,
    GuardDeployOptions,
    MalwareAgentOptions,
    run_agent_scan,
    run_flow_capture,
    start_guard_daemon,
)
from .report import finalize_asset_report

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
    """Deploy agent-host, pull per-asset JSON, assemble an AssetReport."""
    with tempfile.TemporaryDirectory(prefix="fusion-host-") as tmp:
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


def run_flow(target: ScanTarget, options: ScanJobOptions) -> FlowBatch:
    """Deploy agent-flow, run one capture cycle, pull + parse the FlowBatch."""
    with tempfile.TemporaryDirectory(prefix="fusion-flow-") as tmp:
        flow_json = run_flow_capture(
            FlowCaptureOptions(
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
        return FlowBatch.model_validate_json(flow_json.read_text(encoding="utf-8"))


def run_guard(target: ScanTarget, public_url: str) -> ScanResult:
    """Deploy the `agent` binary + start `agent guard --upload <public_url>` as a daemon.

    Returns immediately with the remote PID; the daemon keeps running and pushes
    GuardEventBatches to fusion over time (viewable via /reports/guard-events).
    """
    pid = start_guard_daemon(
        GuardDeployOptions(
            target=target.address,
            upload=public_url,
            port=target.port,
            identity=_identity_for(target),
            password=None,
        )
    )
    return ScanResult(
        kind=ScanCapability.GUARD,
        host_id=target.address,
        pid=pid,
        detail=f"guard daemon started (pid {pid}); events stream to {public_url}",
    )
