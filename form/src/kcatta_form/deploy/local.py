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
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ._util import (
    current_deploy_cancellation_probe,
    expected_files,
    short_id,
    validate_scan_options,
)
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
# Container/image discovery can be prohibitively expensive when the real host root
# includes a large Docker/containerd store. Keep the existing complete-inventory
# default, but let the operator disable only that optional nested scope for local
# scans without weakening the remaining host asset categories.
ENV_LOCAL_SCAN_CONTAINER_ASSETS = "FORM_LOCAL_SCAN_CONTAINER_ASSETS"
# Full-root language project discovery is bounded by depth but can still be
# expensive on development workstations with very large home trees.
ENV_LOCAL_SCAN_PROJECT_DISCOVERY = "FORM_LOCAL_SCAN_PROJECT_DISCOVERY"
_PROCESS_POLL_SECONDS = 0.05
_PROCESS_TERMINATE_GRACE_SECONDS = 0.5


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


def local_scan_container_assets() -> bool:
    """Whether local ``all`` scans include container/image asset discovery."""
    raw = os.getenv(ENV_LOCAL_SCAN_CONTAINER_ASSETS)
    if raw is None or not raw.strip():
        return True
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(
        f"{ENV_LOCAL_SCAN_CONTAINER_ASSETS} must be one of 1/true/yes/on or 0/false/no/off"
    )


def local_scan_project_discovery() -> bool:
    """Whether local scans auto-discover Python/npm project roots."""
    raw = os.getenv(ENV_LOCAL_SCAN_PROJECT_DISCOVERY)
    if raw is None or not raw.strip():
        return True
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(
        f"{ENV_LOCAL_SCAN_PROJECT_DISCOVERY} must be one of 1/true/yes/on or 0/false/no/off"
    )


def _child_env() -> dict[str, str]:
    """Build a child environment without Form/analyzer service credentials."""
    env = dict(os.environ)
    for name in ("FORM_API_TOKEN", "FORM_INGEST_TOKEN", "ANALYZER_INTERNAL_TOKEN"):
        env.pop(name, None)
    return env


def _signal_process_group(process: subprocess.Popen[str], sig: signal.Signals) -> None:
    """Signal the scanner and any helper processes it spawned."""
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, sig)
        elif sig == signal.SIGTERM:  # pragma: no cover - local Form deploys on Linux
            process.terminate()
        else:  # pragma: no cover
            process.kill()
    except ProcessLookupError:
        pass


def _terminate_and_reap(process: subprocess.Popen[str]) -> tuple[str, str]:
    """Terminate a complete scanner process group, escalate, and always reap it."""
    _signal_process_group(process, signal.SIGTERM)
    try:
        return process.communicate(timeout=_PROCESS_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        _signal_process_group(process, signal.SIGKILL)
        return process.communicate()


def _run_agent_process(cmd: list[str], timeout: float | None) -> subprocess.CompletedProcess[str]:
    """Run the local scanner with an active deadline/cancellation process-group fence."""
    cancellation_probe = current_deploy_cancellation_probe()
    if cancellation_probe is not None and cancellation_probe():
        raise InterruptedError("local scan cancelled before process start")

    process = subprocess.Popen(  # noqa: S603 - validated internal argv, never a shell
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        stdin=subprocess.DEVNULL,
        env=_child_env(),
        start_new_session=os.name == "posix",
    )
    started = time.monotonic()
    if cancellation_probe is None and timeout is None:
        stdout, stderr = process.communicate()
    else:
        while True:
            if cancellation_probe is not None and cancellation_probe():
                _terminate_and_reap(process)
                raise InterruptedError("local scan cancelled; scanner process group reaped")

            remaining = None if timeout is None else timeout - (time.monotonic() - started)
            if remaining is not None and remaining <= 0:
                stdout, stderr = _terminate_and_reap(process)
                raise subprocess.TimeoutExpired(
                    cmd,
                    timeout,
                    output=stdout,
                    stderr=stderr,
                )
            wait_for = (
                _PROCESS_POLL_SECONDS
                if remaining is None
                else min(_PROCESS_POLL_SECONDS, max(0.001, remaining))
            )
            try:
                stdout, stderr = process.communicate(timeout=wait_for)
            except subprocess.TimeoutExpired:
                continue
            break
    return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)


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
    posture: bool = True
    secrets: bool = False
    # None → ``local_scan_container_assets()`` (env-overridable; default true).
    container_assets: bool | None = None
    # None → ``local_scan_project_discovery()`` (env-overridable; default true).
    project_discovery: bool | None = None
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
    if opts.malware is not None and opts.malware.signatures is not None:
        from .agent import _require_signature_file

        _require_signature_file(opts.malware.signatures)

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
    container_assets = (
        opts.container_assets
        if opts.container_assets is not None
        else local_scan_container_assets()
    )
    if not container_assets:
        cmd.append("--no-container-assets")
    project_discovery = (
        opts.project_discovery
        if opts.project_discovery is not None
        else local_scan_project_discovery()
    )
    if not project_discovery:
        cmd.append("--no-project-discovery")
    if opts.malware is not None:
        cmd.append("--malware")
        if opts.malware.jobs:
            cmd += ["--malware-jobs", str(int(opts.malware.jobs))]
        if opts.malware.signatures is not None:
            cmd += ["--malware-signatures", str(opts.malware.signatures)]
        if opts.malware.scan_deps:
            cmd.append("--malware-scan-deps")
    if not opts.posture:
        cmd.append("--no-posture")
    if opts.secrets:
        cmd.append("--secrets")

    run = _run_agent_process(cmd, opts.timeout)
    if run.returncode != 0:
        raise RuntimeError(
            f"local agent-collect-host failed (exit {run.returncode})\nstderr: {run.stderr.strip()}"
        )

    wanted = list(expected_files(opts.scan_target))
    files = [out / fname for fname in wanted if (out / fname).is_file()]
    if not files:
        raise RuntimeError(
            f"local scan produced no JSON under {out} (target={opts.scan_target}); "
            f"agent-collect-host stdout: {run.stdout.strip()}"
        )
    missing = [fname for fname in wanted if not (out / fname).is_file()]
    if missing:
        raise RuntimeError(
            "local scan returned an incomplete artifact set; missing " + ", ".join(missing)
        )
    return AgentScanReport(task_id=task_id, files=files)
