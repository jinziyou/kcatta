"""Helpers shared by the SSH and WinRM remote-scan pipelines.

Ports the small pure helpers from the former Rust ``agent-remote`` crate
(``shared.rs``): per-target expected output files, the ``__exit=`` marker
parser, and a local SHA-256 of a file for upload integrity checks.
"""

from __future__ import annotations

import hashlib
import shlex
import uuid
from pathlib import Path

# Scan target -> agent command argument (`agent host -t <arg>`).
SCAN_TARGETS: tuple[str, ...] = (
    "host",
    "packages",
    "sbom",
    "services",
    "accounts",
    "credentials",
    "identity",
    "all",
)

# Per-target per-asset JSON files written by `agent host -o DIR`.
_EXPECTED_FILES: dict[str, tuple[str, ...]] = {
    "host": ("host.json",),
    "packages": ("packages.json",),
    "sbom": ("sbom.cyclonedx.json",),
    "services": ("services.json",),
    "accounts": ("accounts.json",),
    "credentials": ("credentials.json",),
    "identity": ("services.json", "accounts.json", "credentials.json"),
    "all": (
        "host.json",
        "packages.json",
        "sbom.cyclonedx.json",
        "services.json",
        "accounts.json",
        "credentials.json",
    ),
}


def expected_files(target: str) -> tuple[str, ...]:
    """JSON files `agent host -t <target> -o DIR` is expected to produce."""
    try:
        return _EXPECTED_FILES[target]
    except KeyError as exc:
        raise ValueError(
            f"unknown scan target {target!r} (use one of {', '.join(SCAN_TARGETS)})"
        ) from exc


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
