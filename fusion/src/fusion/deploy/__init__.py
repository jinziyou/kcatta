"""Remote scan deployment: ship a kcatta probe to a target, run it, and either
pull results back (host / flow) or leave a daemon running (guard).

This is fusion's cross-machine orchestration layer — the responsibility that used
to live in the Rust ``agent-remote`` crate. The kcatta binaries themselves only
schedule in-process detection on whatever host they run on; getting them onto a
target machine, invoking them, and retrieving results is fusion's job (see the
``fusion-scan`` CLI in :mod:`fusion.cli`).
"""

from __future__ import annotations

from .agent import (
    AgentScanOptions,
    AgentScanReport,
    FlowCaptureOptions,
    GuardDeployOptions,
    MalwareAgentOptions,
    run_agent_scan,
    run_flow_capture,
    start_guard_daemon,
)
from .bootstrap import ensure_key_auth, managed_key_path, revoke_key
from .report import (
    assemble_asset_report,
    attach_malware,
    finalize_asset_report,
    upload_asset_report,
    upload_flow_batch,
    write_asset_report,
)

__all__ = [
    "AgentScanOptions",
    "AgentScanReport",
    "FlowCaptureOptions",
    "GuardDeployOptions",
    "MalwareAgentOptions",
    "run_agent_scan",
    "run_flow_capture",
    "start_guard_daemon",
    "ensure_key_auth",
    "managed_key_path",
    "revoke_key",
    "assemble_asset_report",
    "attach_malware",
    "finalize_asset_report",
    "upload_asset_report",
    "upload_flow_batch",
    "write_asset_report",
]
