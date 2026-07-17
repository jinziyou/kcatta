"""Helpers shared by Form's SSH and WinRM remote-scan pipelines.

Ports the small pure helpers from the former Rust ``agent-remote`` crate
(``shared.rs``): per-target expected output files, the ``__exit=`` marker
parser, and a local SHA-256 of a file for upload integrity checks.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from pathlib import Path

# Form produces uploadable AssetReports, which require host identity.  The
# standalone agent CLI still supports category/SBOM exports; those are not Form
# scan targets because they cannot be represented as a complete report.
SCAN_TARGETS: tuple[str, ...] = (
    "host",
    "all",
)

# Accepted `--windows-packages` profiles (`agent-collect-host --windows-packages <p>`).
WINDOWS_PACKAGE_PROFILES: tuple[str, ...] = ("full", "apps")

DEFAULT_MAX_SCAN_ARTIFACT_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_SCAN_TOTAL_BYTES = 32 * 1024 * 1024
DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS = 30 * 60

_DEPLOY_CANCELLATION_PROBE: ContextVar[Callable[[], bool] | None] = ContextVar(
    "kcatta_deploy_cancellation_probe",
    default=None,
)


@contextmanager
def deploy_cancellation_scope(probe: Callable[[], bool]) -> Iterator[None]:
    """Make one worker's cooperative cancellation visible inside ``to_thread``.

    ``asyncio.to_thread`` copies the caller's context variables into its worker
    thread. Deploy transports capture this probe before starting any helper
    watcher threads, so timeout, operator cancellation, shutdown, and lease loss
    can actively interrupt their current blocking operation.
    """
    token: Token[Callable[[], bool] | None] = _DEPLOY_CANCELLATION_PROBE.set(probe)
    try:
        yield
    finally:
        _DEPLOY_CANCELLATION_PROBE.reset(token)


@contextmanager
def suspend_deploy_cancellation() -> Iterator[None]:
    """Temporarily ignore cancellation for bounded best-effort cleanup."""
    token: Token[Callable[[], bool] | None] = _DEPLOY_CANCELLATION_PROBE.set(None)
    try:
        yield
    finally:
        _DEPLOY_CANCELLATION_PROBE.reset(token)


def current_deploy_cancellation_probe() -> Callable[[], bool] | None:
    """Return the current deploy cancellation probe, if a worker installed one."""
    return _DEPLOY_CANCELLATION_PROBE.get()


def deploy_cancellation_requested() -> bool:
    """Whether the current blocking deploy operation should stop now."""
    probe = current_deploy_cancellation_probe()
    return bool(probe is not None and probe())


def _positive_size_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def max_scan_artifact_bytes() -> int:
    """Maximum bytes accepted for one untrusted remote scan artifact."""
    return _positive_size_env("FORM_MAX_SCAN_ARTIFACT_BYTES", DEFAULT_MAX_SCAN_ARTIFACT_BYTES)


def max_scan_total_bytes() -> int:
    """Maximum aggregate bytes accepted from one remote scan execution."""
    return _positive_size_env("FORM_MAX_SCAN_TOTAL_BYTES", DEFAULT_MAX_SCAN_TOTAL_BYTES)


def remote_command_timeout_seconds() -> float:
    """Hard upper bound for one blocking SSH/WinRM command invocation."""
    raw = os.getenv(
        "FORM_REMOTE_COMMAND_TIMEOUT_SECONDS",
        str(DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS),
    )
    try:
        value = float(raw)
    except ValueError:
        return float(DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS)
    return value if value > 0 else float(DEFAULT_REMOTE_COMMAND_TIMEOUT_SECONDS)


def validate_artifact_file(path: Path) -> int:
    """Validate one local artifact is a bounded regular file and return its size."""
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"scan artifact is not a regular file: {path}")
    size = path.stat().st_size
    limit = max_scan_artifact_bytes()
    if size > limit:
        raise RuntimeError(f"scan artifact {path.name} is {size} bytes; limit is {limit}")
    return size


def validate_artifact_set(paths: list[Path] | tuple[Path, ...]) -> int:
    """Validate per-file and aggregate limits; return aggregate bytes."""
    total = sum(validate_artifact_file(path) for path in dict.fromkeys(paths))
    limit = max_scan_total_bytes()
    if total > limit:
        raise RuntimeError(f"scan artifacts total {total} bytes; limit is {limit}")
    return total


def read_artifact_text(path: Path) -> str:
    """Read UTF-8 only after a size check, then re-check with a bounded read."""
    limit = max_scan_artifact_bytes()
    validate_artifact_file(path)
    with path.open("rb") as handle:
        payload = handle.read(limit + 1)
    if len(payload) > limit:
        raise RuntimeError(f"scan artifact {path.name} grew beyond the {limit}-byte limit")
    return payload.decode("utf-8")


# Per-target per-asset JSON files written by `agent-collect-host -o DIR`.
_EXPECTED_FILES: dict[str, tuple[str, ...]] = {
    "host": ("host.json", "findings.json", "detector-runs.json"),
    "all": (
        "host.json",
        "packages.json",
        "services.json",
        "ports.json",
        "accounts.json",
        "credentials.json",
        "containers.json",
        "images.json",
        "findings.json",
        "detector-runs.json",
    ),
}


def expected_files(target: str) -> tuple[str, ...]:
    """JSON files `agent-collect-host -t <target> -o DIR` is expected to produce."""
    try:
        return _EXPECTED_FILES[target]
    except KeyError as exc:
        raise ValueError(
            f"unknown scan target {target!r} (use one of {', '.join(SCAN_TARGETS)})"
        ) from exc


def validate_scan_options(scan_target: str, windows_packages: str) -> None:
    """Validate operator-supplied scan args against their whitelists *before* they
    are interpolated into a remote shell / PowerShell command. Call this at the
    start of a scan pipeline so a bad value is rejected up front, never executed.
    """
    if scan_target == "sbom":
        raise ValueError(
            "scan_target='sbom' is a standalone CycloneDX export and cannot form an "
            "uploadable host report; use agent-collect-host -t sbom directly"
        )
    if scan_target not in SCAN_TARGETS:
        raise ValueError(
            f"unsupported Form scan target {scan_target!r} (use one of {', '.join(SCAN_TARGETS)})"
        )
    if windows_packages not in WINDOWS_PACKAGE_PROFILES:
        raise ValueError(
            f"unknown windows-packages profile {windows_packages!r} "
            f"(use one of {', '.join(WINDOWS_PACKAGE_PROFILES)})"
        )


def short_id() -> str:
    """Eight hex chars, used as the remote work-dir suffix."""
    return uuid.uuid4().hex[:8]


def sh_quote(value: str) -> str:
    """POSIX single-quote escaping for values interpolated into remote shells."""
    return shlex.quote(value)


def parse_marked_exit(stdout: str) -> int | None:
    """Read the last ``__exit=<n>`` marker line from captured stdout."""
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if stripped.startswith("__exit="):
            try:
                return int(stripped.removeprefix("__exit="))
            except ValueError:
                return None
    return None


def sha256_file(path: Path) -> str:
    """Lowercase hex SHA-256 of a local file (matches `sha256sum` output)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_user_host(target: str) -> tuple[str, str]:
    """Split ``user@host`` into its parts, validating both are non-empty."""
    user, sep, host = target.partition("@")
    if not sep or not user or not host:
        raise ValueError(f"target must be user@host, got {target!r}")
    return user, host
