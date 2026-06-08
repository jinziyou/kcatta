"""Remote scan deployment: ship the ``agent`` probe to a target, run it, pull
results back, and assemble an :class:`~fusion.schemas.AssetReport`.

This is fusion's cross-machine orchestration layer — the responsibility that used
to live in the Rust ``agent-remote`` crate. ``agent`` itself now only schedules
in-process detection modules on whatever host it runs on; getting it onto a
target machine, invoking it, and retrieving results is fusion's job (see the
``fusion-scan`` CLI in :mod:`fusion.cli`).
"""

from __future__ import annotations

from .agent import (
    AgentScanOptions,
    AgentScanReport,
    MalwareAgentOptions,
    run_agent_scan,
)
from .bootstrap import ensure_key_auth, managed_key_path, revoke_key
from .report import (
    assemble_asset_report,
    attach_malware,
    finalize_asset_report,
    upload_asset_report,
    write_asset_report,
)

__all__ = [
    "AgentScanOptions",
    "AgentScanReport",
    "MalwareAgentOptions",
    "run_agent_scan",
    "ensure_key_auth",
    "managed_key_path",
    "revoke_key",
    "assemble_asset_report",
    "attach_malware",
    "finalize_asset_report",
    "upload_asset_report",
    "write_asset_report",
]
