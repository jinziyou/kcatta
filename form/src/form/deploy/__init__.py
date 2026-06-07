"""Remote scan deployment: ship the ``fusion`` probe to a target, run it, pull
results back, and assemble an :class:`~form.schemas.AssetReport`.

This is form's cross-machine orchestration layer — the responsibility that used
to live in the Rust ``fusion-remote`` crate. ``fusion`` itself now only schedules
in-process detection modules on whatever host it runs on; getting it onto a
target machine, invoking it, and retrieving results is form's job (see the
``form-scan`` CLI in :mod:`form.cli`).
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
