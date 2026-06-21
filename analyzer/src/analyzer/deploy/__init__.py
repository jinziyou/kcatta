"""Remote scan deployment: ship a kcatta probe to a target, run it, and either
pull results back (host / flow) or leave a daemon running (guard).

This is analyzer's cross-machine orchestration layer — the responsibility that used
to live in the Rust ``agent-remote`` crate. The kcatta binaries themselves only
schedule in-process detection on whatever host they run on; getting them onto a
target machine, invoking them, and retrieving results is analyzer's job (see the
``analyzer-scan`` CLI in :mod:`analyzer.cli`).
"""

from __future__ import annotations

from .agent import (
    AgentScanOptions,
    AgentScanReport,
    GuardDeployOptions,
    GuardStatus,
    MalwareAgentOptions,
    TraceCaptureOptions,
    guard_status,
    run_agent_scan,
    run_trace_capture,
    start_guard_daemon,
)
from .bootstrap import ensure_key_auth, managed_key_path, revoke_key
from .local import LocalScanOptions, local_scan_root, run_local_agent_scan
from .report import (
    assemble_asset_report,
    attach_malware,
    finalize_asset_report,
    upload_asset_report,
    upload_trace_batch,
    write_asset_report,
)

__all__ = [
    "AgentScanOptions",
    "AgentScanReport",
    "TraceCaptureOptions",
    "GuardDeployOptions",
    "GuardStatus",
    "MalwareAgentOptions",
    "guard_status",
    "run_agent_scan",
    "run_trace_capture",
    "start_guard_daemon",
    "LocalScanOptions",
    "local_scan_root",
    "run_local_agent_scan",
    "ensure_key_auth",
    "managed_key_path",
    "revoke_key",
    "assemble_asset_report",
    "attach_malware",
    "finalize_asset_report",
    "upload_asset_report",
    "upload_trace_batch",
    "write_asset_report",
]
