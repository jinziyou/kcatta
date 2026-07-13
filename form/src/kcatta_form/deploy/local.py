"""Local host scan: run the bundled agent-collect-host on Form's own machine.

The cross-machine path (`agent.run_agent_scan`) ships agent-collect-host to a target over
SSH/WinRM. This is its **local** sibling: when the target *is* the Form host,
there is no transport — run the locally-resolved static ``agent-collect-host`` binary
directly via subprocess against a local filesystem root, then return the same
per-asset JSON files the remote path produces (assembled into an ``AssetReport``
by the same :func:`report.finalize_asset_report`). Reuses the exact bundled musl
binary the deploy layer already ships (``resolve_agent_binary``).

Scan root: defaults to ``/``. In a containerized Form, ``/`` is the *container*
filesystem; to scan the real host, bind-mount it (e.g. ``-v /:/host:ro``) and set
``FORM_LOCAL_SCAN_ROOT=/host``.
"""

from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ._util import expected_files, short_id, validate_scan_options
from .agent import (
    _ARCH_ALIASES,
    AgentScanReport,
    MalwareAgentOptions,
    _require_binary,
    resolve_agent_binary,
)

# Free-text default address/label for a registered local target.
LOCAL_ADDRESS = "localhost"
# Override the local filesystem root (e.g. a host bind-mount inside a container).
ENV_LOCAL_SCAN_ROOT = "FORM_LOCAL_SCAN_ROOT"


def local_arch() -> str:
    """Normalized arch of the Form host (`x86_64` | `aarch64`), else raise."""
    raw = platform.machine()
    arch = _ARCH_ALIASES.get(raw)
    if arch is None:
        supported = sorted(set(_ARCH_ALIASES.values()))
        raise RuntimeError(f"local arch {raw!r} not supported (shipped: {supported})")
    return arch


def local_scan_root() -> str:
    """Default local filesystem root to scan (`FORM_LOCAL_SCAN_ROOT` or `/`)."""
    return os.getenv(ENV_LOCAL_SCAN_ROOT) or "/"


def _child_env() -> dict[str, str]:
    """Build a child environment without Form/analyzer service credentials."""
    env = dict(os.environ)
    for name in ("FORM_API_TOKEN", "FORM_INGEST_TOKEN", "ANALYZER_INTERNAL_TOKEN"):
        env.pop(name, None)
    return env


@dataclass
class LocalScanOptions:
    """Parameters for :func:`run_local_agent_scan`."""

    output_dir: Path
    # Explicit binary override; when None, resolved from the local host's arch.
    agent_binary: Path | None = None
    scan_target: str = "host"
    # None → `local_scan_root()` (env-overridable; default `/`).
    scan_root: str | None = None
    windows_packages: str = "apps"
    malware: MalwareAgentOptions | None = None
    task_id: str | None = None
    # subprocess deadline (seconds); None → no deadline. The API path plumbs the job
    # timeout here so subprocess.run actually KILLS agent-collect-host on overrun —
    # asyncio.wait_for alone can't interrupt a blocking call in a thread-pool worker.
    timeout: float | None = None


def run_local_agent_scan(opts: LocalScanOptions) -> AgentScanReport:
    """Run the bundled ``agent-collect-host`` on the local filesystem and return its files.

    No SSH, no remote work dir: execute the locally-resolved static binary directly
    against ``scan_root`` (default ``/`` or ``FORM_LOCAL_SCAN_ROOT``), writing
    per-asset JSON into ``output_dir`` — the same ``-o DIR`` contract the remote
    path uses, so :func:`report.finalize_asset_report` assembles it identically.
    """
    task_id = opts.task_id or short_id()
    # Whitelist scan_target / windows_packages (also the remote path's primary guard).
    validate_scan_options(opts.scan_target, opts.windows_packages)

    arch = local_arch()
    binary = resolve_agent_binary(arch, "agent-collect-host", opts.agent_binary)
    _require_binary(binary, arch)

    # root is operator-controlled (CLI flag / FORM_LOCAL_SCAN_ROOT), never
    # request-derived, and is passed as an argv element (no shell) — so there is no
    # remote path-traversal / injection surface here.
    root = opts.scan_root if opts.scan_root is not None else local_scan_root()
    out = opts.output_dir
    out.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        str(binary),
        "-r",
        root,
        "-t",
        opts.scan_target,
        "--windows-packages",
        opts.windows_packages,
        "-o",
        str(out),
    ]
    if opts.malware is not None:
        cmd.append("--malware")
        if opts.malware.jobs:
            cmd += ["--malware-jobs", str(int(opts.malware.jobs))]

    run = subprocess.run(  # noqa: S603 - argv list (no shell); binary + flags are validated/internal
        cmd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=opts.timeout,
        env=_child_env(),
    )
    if run.returncode != 0:
        raise RuntimeError(
            f"local agent-collect-host failed (exit {run.returncode})\nstderr: {run.stderr.strip()}"
        )

    wanted = list(expected_files(opts.scan_target))
    if opts.malware is not None:
        wanted.append("malware.json")
    files = [out / fname for fname in wanted if (out / fname).is_file()]
    if not files:
        raise RuntimeError(
            f"local scan produced no JSON under {out} (target={opts.scan_target}); "
            f"agent-collect-host stdout: {run.stdout.strip()}"
        )
    return AgentScanReport(task_id=task_id, files=files)
