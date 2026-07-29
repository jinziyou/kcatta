"""Form-owned SSH agent-mode remote scan.

Ship the static capability binary selected for the requested scan over SSH,
run it in place against the live target, pull the JSON artifact back, then
clean up one-shot work dirs. Guard deployment is the persistent exception: it
ships `agentd` and starts `agentd respond --upload` as a resident daemon.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import math
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from ..public_url import normalize_public_origin
from ..schemas import (
    AgentCertificateBundle,
    AgentCertificateState,
    AgentIdentityState,
)
from . import bootstrap
from ._util import (
    expected_files,
    parse_marked_exit,
    remote_command_timeout_seconds,
    sh_quote,
    sha256_file,
    short_id,
    split_user_host,
    validate_scan_options,
)
from .ssh import SshSession

logger = logging.getLogger(__name__)

# A token safe to place verbatim in an env file that is both sourced by a shell
# (setsid fallback) and read by systemd `EnvironmentFile=`. Form's generated
# tokens are `secrets.token_urlsafe` / hex / base64, all within this set; a token
# with whitespace, quotes, `$`, backticks, or control chars is rejected so it can
# break neither parser.
_ENV_TOKEN_SAFE = re.compile(r"\A[A-Za-z0-9._~=+/-]+\Z")

# Guard binaries/config remain separately uninstallable under /var/lib/agent-guard.
# Agent identity survives that lifecycle in this fixed, private location. Each
# generation is staged fully, then a single atomic symlink replacement publishes
# the stable paths consumed by agentd's hot-reloading HTTP client.
AGENT_IDENTITY_DIR = "/var/lib/kcatta/agentd/identity"
AGENT_IDENTITY_CURRENT = f"{AGENT_IDENTITY_DIR}/current"
AGENT_CERT_PATH = f"{AGENT_IDENTITY_CURRENT}/client-cert.pem"
AGENT_KEY_PATH = f"{AGENT_IDENTITY_CURRENT}/client-key.pem"
AGENT_CA_PATH = f"{AGENT_IDENTITY_CURRENT}/ca-bundle.pem"

GUARD_DEPLOYMENT_MANIFEST_NAME = "deployment-manifest.json"
GUARD_READY_FILE_NAME = "guard.ready"
_GUARD_MANIFEST_VERSION = 1
_GUARD_DEPLOYMENT_ID = re.compile(r"\A[0-9a-f]{32}\Z")

_IDENTITY_FILE_NAMES = {
    "certificate": "client-cert.pem",
    "private_key": "client-key.pem",
    "ca": "ca-bundle.pem",
}
_IDENTITY_GENERATION_NAME = re.compile(r"\Ageneration-[1-9][0-9]*-[0-9a-f]{16}\Z")


def _token_is_env_safe(token: str) -> bool:
    """Whether ``token`` can be written verbatim into the guard daemon env file."""
    return bool(_ENV_TOKEN_SAFE.match(token))


def _legacy_ingest_token(api_token: str | None) -> str | None:
    token = (api_token if api_token is not None else os.getenv("FORM_INGEST_TOKEN") or "").strip()
    if not token:
        return None
    if not _token_is_env_safe(token):
        raise ValueError("FORM_INGEST_TOKEN contains characters unsafe for an environment file")
    return token


# Candidate work-dir parents, in priority order. First writable, non-`noexec`
# one wins.
WORKDIR_CANDIDATES: tuple[str, ...] = (
    "/var/lib/scdr",
    "/opt/scdr",
    "/root/.cache/scdr",
    "/tmp",
)


@dataclass
class MalwareAgentOptions:
    """Run malware scanning with optional Form-managed signature extensions."""

    jobs: int | None = None
    signatures: Path | None = None
    scan_deps: bool = False


@dataclass
class AgentScanOptions:
    """Parameters for :func:`run_agent_scan`."""

    target: str  # user@host
    output_dir: Path
    # Explicit binary override; when None, resolved from the target's probed arch.
    agent_binary: Path | None = None
    scan_target: str = "host"
    scan_root: str = "/"
    port: int = 22
    identity: Path | None = None
    password: str | None = None
    task_id: str | None = None
    windows_packages: str = "apps"
    malware: MalwareAgentOptions | None = None
    posture: bool = True
    secrets: bool = False


@dataclass
class AgentScanReport:
    """Result of a successful remote agent scan."""

    task_id: str
    files: list[Path] = field(default_factory=list)


class _RemoteWorkdir:
    """RAII guard: ``rm -rf`` the remote work dir on exit, even on error."""

    def __init__(self, session: SshSession, task_id: str) -> None:
        self._session = session
        parent, created = _pick_workdir_parent(session)
        self.parent = parent
        self._created_parent = created
        self.path = f"{parent}/scan-{task_id}"
        quoted = sh_quote(self.path)
        out = session.exec(f"mkdir -p {quoted} && chmod 700 {quoted} && echo __ok")
        if not out.success or "__ok" not in out.stdout:
            raise RuntimeError(
                f"failed to create remote work dir {self.path}: {out.stderr.strip()}"
            )

    def __enter__(self) -> _RemoteWorkdir:
        return self

    def __exit__(self, *_exc: object) -> None:
        # Guard against empty/wildcard paths before rm -rf.
        if not (self.path.startswith("/") and "/scan-" in self.path):
            return
        try:
            self._session.exec(f"rm -rf {sh_quote(self.path)}")
        except Exception as exc:  # noqa: BLE001 - cleanup must never mask the real error
            logger.warning("cleanup rm -rf %s failed: %s", self.path, exc)
        # Remove the scdr parent we created, only when empty and clearly ours.
        if self._created_parent and self.parent.startswith("/") and self.parent.endswith("/scdr"):
            with contextlib.suppress(Exception):
                self._session.exec(f"rmdir {sh_quote(self.parent)} 2>/dev/null")


def _interruptible_one_shot_command(command: str) -> str:
    """Wrap a remote one-shot child so SSH channel loss reaps it on the target."""
    return (
        "kcatta_child=''; "
        'trap \'if [ -n "$kcatta_child" ]; then '
        'kill -TERM "$kcatta_child" 2>/dev/null; sleep 1; '
        'kill -KILL "$kcatta_child" 2>/dev/null; '
        'wait "$kcatta_child" 2>/dev/null; fi; exit 130\' HUP INT TERM; '
        f"{command} & kcatta_child=$!; "
        'wait "$kcatta_child"; kcatta_status=$?; '
        "trap - HUP INT TERM; echo __exit=$kcatta_status"
    )


def run_agent_scan(opts: AgentScanOptions) -> AgentScanReport:
    """Run the full agent pipeline: bootstrap auth, upload, exec, pull, cleanup."""
    task_id = opts.task_id or short_id()

    # Reject unknown scan_target / windows_packages BEFORE building the remote
    # command (these flow into the target shell). Quoting below is defense in
    # depth; this whitelist is the primary guard.
    validate_scan_options(opts.scan_target, opts.windows_packages)
    signatures = opts.malware.signatures if opts.malware is not None else None
    if signatures is not None:
        _require_signature_file(signatures)

    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)

    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        arch = _probe_arch(session)
        binary = resolve_agent_binary(arch, "agent-collect-host", opts.agent_binary)
        _require_binary(binary, arch)
        with _RemoteWorkdir(session, task_id) as workdir:
            remote_bin = f"{workdir.path}/agent-collect-host"
            remote_out = f"{workdir.path}/out"

            session.upload(binary, remote_bin)
            _verify_upload(session, binary, remote_bin)

            remote_signatures: str | None = None
            if signatures is not None:
                remote_signatures = f"{workdir.path}/malware-signatures.json"
                session.upload(signatures, remote_signatures)
                _verify_upload(session, signatures, remote_signatures)

            q_bin = sh_quote(remote_bin)
            q_out = sh_quote(remote_out)
            # agent-collect-host is a single-command binary (no `host` subcommand).
            agent_command = (
                f"{q_bin} -r {sh_quote(opts.scan_root)} -t {sh_quote(opts.scan_target)} "
                f"--windows-packages {sh_quote(opts.windows_packages)} -o {q_out}"
            )
            if opts.malware is not None:
                agent_command += " --malware"
                if opts.malware.jobs:
                    agent_command += f" --malware-jobs {int(opts.malware.jobs)}"
                if remote_signatures is not None:
                    agent_command += f" --malware-signatures {sh_quote(remote_signatures)}"
                if opts.malware.scan_deps:
                    agent_command += " --malware-scan-deps"
            if not opts.posture:
                agent_command += " --no-posture"
            if opts.secrets:
                agent_command += " --secrets"
            command = (
                f"chmod +x {q_bin} && mkdir -p {q_out} && "
                f"{_interruptible_one_shot_command(agent_command)}"
            )

            run = session.exec(command)
            if parse_marked_exit(run.stdout) != 0:
                raise RuntimeError(
                    f"remote agent-collect-host failed (exit {parse_marked_exit(run.stdout)})\n"
                    f"stdout: {run.stdout.strip()}\nstderr: {run.stderr.strip()}"
                )

            opts.output_dir.mkdir(parents=True, exist_ok=True)
            wanted = list(expected_files(opts.scan_target))

            files: list[Path] = []
            missing: list[str] = []
            for fname in wanted:
                remote_file = f"{remote_out}/{fname}"
                if not _remote_exists(session, remote_file):
                    missing.append(fname)
                    continue
                local_file = opts.output_dir / fname
                session.download(remote_file, local_file)
                files.append(local_file)

            if missing:
                raise RuntimeError(
                    "remote scan returned an incomplete artifact set; missing " + ", ".join(missing)
                )

            if not files:
                raise RuntimeError(
                    f"remote scan produced no JSON under {remote_out} "
                    f"(target={opts.scan_target}); nothing pulled back"
                )

    return AgentScanReport(task_id=task_id, files=files)


def _pick_workdir_parent(session: SshSession) -> tuple[str, bool]:
    """First writable, non-`noexec` candidate parent dir. Returns (dir, created)."""
    parts = []
    for cand in WORKDIR_CANDIDATES:
        parts.append(
            f"pre=1; [ -d {cand} ] || pre=0; "
            f"if mkdir -p {cand} 2>/dev/null && [ -w {cand} ]; then "
            "  opts=$(awk -v d=" + cand + " '$2==d || (index(d,$2)==1 && length($2)>best)"
            "{best=length($2);o=$4} END{print o}' /proc/self/mounts); "
            f'  case ",$opts," in *,noexec,*) : ;; *) echo "{cand} $pre"; exit 0;; esac; '
            "fi"
        )
    out = session.exec("\n".join(parts))
    chosen = out.stdout.strip().splitlines()
    first = chosen[0].strip() if chosen else ""
    if not first:
        raise RuntimeError(
            f"no writable non-noexec work dir among {WORKDIR_CANDIDATES} on {session.target}"
        )
    directory, _, pre = first.rpartition(" ")
    directory = (directory or first).strip()
    return directory, pre.strip() == "0"


# Target arch → the musl triple whose static binaries we ship. `uname -m`
# strings are normalized (amd64→x86_64, arm64→aarch64).
_ARCH_TRIPLE = {
    "x86_64": "x86_64-unknown-linux-musl",
    "aarch64": "aarch64-unknown-linux-musl",
}
_ARCH_ALIASES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


def _probe_arch(session: SshSession) -> str:
    """Return the target's normalized arch (`x86_64` | `aarch64`), else raise."""
    raw = session.exec("uname -m").stdout.strip()
    arch = _ARCH_ALIASES.get(raw)
    if arch is None:
        raise RuntimeError(f"target arch {raw!r} not supported (shipped: {sorted(_ARCH_TRIPLE)})")
    return arch


def _agent_target_dir() -> Path:
    """Cargo target root on the Form host holding per-arch release directories."""
    return Path(os.getenv("FORM_AGENT_TARGET_DIR", "../agent/target"))


def resolve_windows_agent_binary(
    name: str = "agent-collect-host.exe", explicit: Path | None = None
) -> Path:
    """Resolve the Windows agent binary (WinRM needs PE, not the musl build).

    The official Linux-built Form image carries the GNU-target artifact. A
    native MSVC build remains a supported operator override/fallback.
    """
    if explicit is not None:
        return explicit
    configured = os.getenv("FORM_WINDOWS_AGENT_BINARY", "").strip()
    if configured:
        return Path(configured).expanduser()
    target_dir = _agent_target_dir()
    candidates = [
        target_dir / "x86_64-pc-windows-gnu" / "release" / name,
        target_dir / "x86_64-pc-windows-msvc" / "release" / name,
    ]
    return next((path for path in candidates if path.is_file()), candidates[0])


def resolve_agent_binary(arch: str, name: str, explicit: Path | None) -> Path:
    """Pick the deploy binary for ``arch``: an explicit override wins; otherwise the
    ``<target>/<triple>/release/<name>`` produced by ``make build-agent-deploy``."""
    if explicit is not None:
        return explicit
    return _agent_target_dir() / _ARCH_TRIPLE[arch] / "release" / name


def _require_binary(binary: Path, arch: str) -> None:
    """Raise a build-hint error if the resolved deploy binary is missing."""
    if binary.is_file():
        return
    suffix = "-arm64" if arch == "aarch64" else ""
    raise FileNotFoundError(
        f"agent binary not found for {arch}: {binary}\n"
        "build the static deploy binaries first (from the kcatta/ repo root):\n"
        f"  make build-agent-deploy{suffix}"
    )


def _require_signature_file(path: Path) -> None:
    """Validate the Form-managed signature extension before remote side effects."""
    # Follow server-managed symlinks so Kubernetes/Docker secret mounts work;
    # the path cannot originate in the client request.
    if not path.is_file():
        raise FileNotFoundError(f"malware signature file is not a regular file: {path}")


def _require_detection_data_file(path: Path, label: str) -> None:
    """Validate one server-managed detector input before remote side effects."""
    if not path.is_file():
        raise FileNotFoundError(f"{label} is not a regular file: {path}")
    size = path.stat().st_size
    if size <= 0:
        raise ValueError(f"{label} is empty: {path}")
    # Threat adapters themselves cap downloads at 64 MiB.  Keep the deployment
    # boundary equally bounded so a mistaken server path cannot fill a remote
    # work directory or Guard install.
    if size > 64 * 1024 * 1024:
        raise ValueError(f"{label} exceeds the 64 MiB deployment limit: {path}")


def _verify_upload(
    session: SshSession,
    local: Path,
    remote_path: str,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> None:
    local_sum = sha256_file(local)
    out = session.exec(f"{_guard_lock_fence(lock)}sha256sum {sh_quote(remote_path)} 2>/dev/null")
    remote_sum = out.stdout.split()[0] if out.stdout.split() else ""
    if not remote_sum:
        logger.warning("sha256sum unavailable on %s; skipping upload integrity check", session.host)
        return
    if remote_sum != local_sum:
        raise RuntimeError(
            f"uploaded file sha256 mismatch (local {local_sum}, remote {remote_sum})"
        )


def _remote_exists(
    session: SshSession,
    path: str,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> bool:
    return (
        "__y"
        in session.exec(f"{_guard_lock_fence(lock)}test -f {sh_quote(path)} && echo __y").stdout
    )


# --------------------------------------------------------------------------
# Trace capture (one-shot) and guard (persistent daemon) remote scheduling.
# Trace mirrors the host pipeline: SSH in, deploy the lean capability binary,
# run it once, and pull the TraceBatch back. Guard deploys the `agentd`
# umbrella and leaves it running because only `agentd` owns upload.
# --------------------------------------------------------------------------


@dataclass
class TraceCaptureOptions:
    """Parameters for :func:`run_trace_capture` (deploy + one-shot agent-collect-trace)."""

    target: str  # user@host
    output_dir: Path
    # Explicit agent-collect-trace override; when None, resolved from the target's arch.
    agent_binary: Path | None = None
    port: int = 22
    identity: Path | None = None
    password: str | None = None
    task_id: str | None = None
    pcap: bool = False
    iface: str = "any"
    duration: int = 5
    bpf: str = "tcp or udp or icmp"
    # Form-managed, already-synchronised feed. None is an explicit collect-only
    # run and becomes --no-intel (never a silent unenriched "detection" pass).
    intel: Path | None = None
    # Requires a custom deploy binary built with the eBPF feature. The Form
    # trigger gates this with FORM_TRACE_EBPF_ENABLED before any SSH mutation.
    ebpf: bool = False


def _trace_capture_args(opts: TraceCaptureOptions) -> str:
    """Backend arguments for a Form-managed trace; never returns mock."""
    if opts.pcap:
        args = (
            f" --pcap --iface {sh_quote(opts.iface)} "
            f"--duration {max(1, int(opts.duration))} --bpf {sh_quote(opts.bpf)}"
        )
    else:
        args = f" --winnet --duration {max(1, int(opts.duration))}"
    if opts.ebpf:
        args += f" --ebpf --ebpf-duration {max(1, int(opts.duration))}"
    return args


def run_trace_capture(opts: TraceCaptureOptions) -> Path:
    """Deploy agent-collect-trace, run one capture cycle, pull the `TraceBatch` JSON back.

    Returns the local path to the pulled `flow.json`. The default uses the live
    OS connection-table backend (``--winnet``); ``opts.pcap`` selects a custom
    deploy binary built with libpcap support. Form never selects mock telemetry.
    """
    task_id = opts.task_id or short_id()
    if opts.intel is not None:
        _require_detection_data_file(opts.intel, "trace IOC feed")
    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)

    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        arch = _probe_arch(session)
        binary = resolve_agent_binary(arch, "agent-collect-trace", opts.agent_binary)
        _require_binary(binary, arch)
        with _RemoteWorkdir(session, task_id) as workdir:
            remote_bin = f"{workdir.path}/agent-collect-trace"
            remote_out = f"{workdir.path}/flow.json"
            remote_intel = f"{workdir.path}/trace-intel.json"

            session.upload(binary, remote_bin)
            _verify_upload(session, binary, remote_bin)
            if opts.intel is not None:
                session.upload(opts.intel, remote_intel)
                _verify_upload(session, opts.intel, remote_intel)

            q_bin = sh_quote(remote_bin)
            capture_command = f"{q_bin} capture --out {sh_quote(remote_out)}"
            capture_command += _trace_capture_args(opts)
            capture_command += (
                f" --intel {sh_quote(remote_intel)}" if opts.intel is not None else " --no-intel"
            )
            command = f"chmod +x {q_bin} && {_interruptible_one_shot_command(capture_command)}"

            run = session.exec(command)
            if parse_marked_exit(run.stdout) != 0:
                raise RuntimeError(
                    "remote agent-collect-trace capture failed "
                    f"(exit {parse_marked_exit(run.stdout)})\n"
                    f"stdout: {run.stdout.strip()}\nstderr: {run.stderr.strip()}"
                )
            if not _remote_exists(session, remote_out):
                raise RuntimeError(f"remote capture produced no TraceBatch at {remote_out}")

            opts.output_dir.mkdir(parents=True, exist_ok=True)
            local = opts.output_dir / "flow.json"
            session.download(remote_out, local)

    return local


@dataclass
class GuardDeployOptions:
    """Parameters for :func:`start_guard_daemon` (deploy + start `agentd respond`)."""

    target: str  # user@host
    upload: str  # Form base URL the daemon pushes GuardEventBatch to
    # The `agentd` umbrella binary (uploading lives there); None → resolved by arch.
    agent_binary: Path | None = None
    install_dir: str = "/var/lib/agent-guard"
    config: Path | None = None  # local guard.json to upload (optional)
    port: int = 22
    identity: Path | None = None
    password: str | None = None
    # Ingest-scoped bearer token the remote daemon sends to Form. Injected via a
    # 0600 environment file and never exposed on the command line.
    api_token: str | None = field(default=None, repr=False)
    # systemd unit name for the supervised daemon (deterministic per host so the
    # status probe can find it). Validated to a safe charset before use.
    unit_name: str = "kcatta-guard"
    # One-time per-Agent mTLS material. Appended after all legacy fields to keep
    # positional construction compatible. When present it takes precedence over
    # api_token and is excluded from repr.
    certificate_bundle: AgentCertificateBundle | None = field(default=None, repr=False)
    # Called only after the remote daemon reports started, while the same SSH
    # session is still available for rollback. Form uses this to activate the
    # staged central generation before the remote previous pointer is discarded.
    activation_callback: Callable[[], None] | None = field(default=None, repr=False)
    # Detector inputs are server-owned paths. They are transactionally
    # published beside guard.json and restored together on deployment rollback.
    intel: Path | None = None
    malware_signatures: Path | None = None


@dataclass(frozen=True)
class GuardDeploymentManifest:
    """Server-owned proof of the exact Guard generation running remotely."""

    deployment_id: str
    identity_generation: str | None
    binary_sha256: str
    config_sha256: str | None
    pid: str
    unit_name: str
    binary_path: str
    config_path: str | None


class GuardDeploymentUncertainError(RuntimeError):
    """Remote side effects may have committed but rollback could not be proven."""

    def __init__(
        self,
        *,
        target: str,
        deployment_id: str,
        identity_generation: str | None,
    ) -> None:
        self.target = target
        self.deployment_id = deployment_id
        self.identity_generation = identity_generation
        super().__init__(
            f"Guard deployment outcome is uncertain for {target}; "
            f"reconcile remote manifest {deployment_id} before aborting"
        )


class GuardDeploymentConflictError(RuntimeError):
    """A conditional teardown no longer owns the remote Guard generation."""


class _RemoteRollbackUncertainError(RuntimeError):
    """Internal marker: a helper could not prove its local rollback."""


# systemd unit / setsid markers parsed back from remote stdout.
_GUARD_UNIT_MARKER = "__unit="
_GUARD_PID_MARKER = "__pid="

# A systemd unit name must be a plain token (letters/digits/-_.@); reject
# anything else so it can never break out of the systemd-run invocation.
_UNIT_NAME_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@")


def _validate_unit_name(name: str) -> str:
    if not name or any(c not in _UNIT_NAME_OK for c in name):
        raise ValueError(f"invalid systemd unit name {name!r}")
    return name


def _validate_guard_install_dir(path: str) -> str:
    """Reject aliases/shallow paths before any privileged remote mutation."""

    if not isinstance(path, str) or not path or len(path) > 1024:
        raise ValueError("Guard install directory must be a non-empty absolute path")
    if path.startswith("//") or any(
        ord(character) < 32 or ord(character) == 127 for character in path
    ):
        raise ValueError("Guard install directory contains unsafe characters")
    normalized = PurePosixPath(path)
    if (
        not normalized.is_absolute()
        or ".." in normalized.parts
        or str(normalized) != path
        or len(normalized.parts) < 3
    ):
        raise ValueError(
            "Guard install directory must be a normalized absolute path below a parent directory"
        )
    return path


def _prepare_guard_install_over(session: SshSession, install: str) -> None:
    """Create/tighten a real private directory; never follow a final symlink."""

    q_install = sh_quote(_validate_guard_install_dir(install))
    result = session.exec(
        f"if [ -L {q_install} ] || "
        f"{{ [ -e {q_install} ] && [ ! -d {q_install} ]; }}; then exit 42; fi; "
        f"mkdir -p {q_install} && [ -d {q_install} ] && [ ! -L {q_install} ] "
        f"&& chmod 700 {q_install} && echo __ok"
    )
    if not result.success or "__ok" not in result.stdout:
        raise RuntimeError(f"failed to prepare private Guard install directory {install}")


def start_guard_daemon(opts: GuardDeployOptions) -> str:
    """Deploy the `agentd` umbrella binary and start `agentd respond` as a supervised daemon.

    Prefers **systemd** (``systemd-run --unit=<unit> --property=Restart=on-failure``)
    so the daemon is auto-restarted if it crashes / is OOM-killed — the B5 gap
    where a bare ``setsid`` daemon dying meant endpoint protection silently
    vanished. When systemd is unavailable the start falls back to the previous
    detached ``setsid`` form. Returns the remote PID.

    The daemon keeps running after the SSH session closes and pushes
    `GuardEventBatch`es to ``opts.upload``. Unlike the one-shot host/flow paths,
    this intentionally does **not** clean up — the install dir and the running
    process persist.

    Uses the `agentd` binary (not the lean `agent-respond`): uploading lives in the
    umbrella, so `agentd respond --upload <form>` pushes events through Form.
    """
    unit = _validate_unit_name(opts.unit_name)
    install = _validate_guard_install_dir(opts.install_dir)
    if opts.intel is not None:
        _require_detection_data_file(opts.intel, "Guard IOC feed")
    if opts.malware_signatures is not None:
        _require_detection_data_file(opts.malware_signatures, "Guard malware signatures")
    if opts.certificate_bundle is not None:
        # Validate before key bootstrap, binary upload, or any remote mutation.
        _validate_agent_certificate_bundle(opts.certificate_bundle)
        normalize_public_origin(
            opts.upload,
            label="per-Agent mTLS Form upload URL",
        )
    else:
        # Preserve auth-off compatibility, but reject an unsafe explicit/env
        # token before installing or starting anything.
        _legacy_ingest_token(opts.api_token)
    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)

    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        arch = _probe_arch(session)
        binary = resolve_agent_binary(arch, "agentd", opts.agent_binary)
        _require_binary(binary, arch)
        _prepare_guard_install_over(session, install)

        remote_bin = f"{install}/agentd"
        staged_bin = f"{install}/.agentd-{short_id()}.new"
        remote_cfg = f"{install}/guard.json"
        remote_intel = f"{install}/trace-intel.json"
        remote_signatures = f"{install}/malware-signatures.json"
        remote_env = f"{install}/agentd.env"
        identity_generation = (
            agent_identity_generation_name(
                opts.certificate_bundle.certificate.generation,
                opts.certificate_bundle.certificate.cert_sha256,
            )
            if opts.certificate_bundle is not None
            else None
        )
        binary_sha256 = sha256_file(binary)
        config_sha256 = sha256_file(opts.config) if opts.config is not None else None
        expected_manifest = _build_guard_deployment_manifest(
            identity_generation=identity_generation,
            binary_sha256=binary_sha256,
            config_sha256=config_sha256,
            pid="1",
            unit=unit,
            remote_bin=remote_bin,
            remote_cfg=remote_cfg if opts.config is not None else None,
        )
        lock = _acquire_guard_deployment_lock(session, install)
        try:
            # Rollback baselines must come from the state protected by this
            # exact owner. Reading them before acquisition can observe another
            # transaction's temporary stop/half-publication and later roll a
            # committed deployment back to that intermediate state.
            previous_guard = _guard_status_over(session, unit, install, lock=lock)
            previous_config_exists = _remote_exists(session, remote_cfg, lock=lock)
            previous_env_exists = _remote_exists(session, remote_env, lock=lock)
        except BaseException:
            _release_guard_deployment_lock(session, lock)
            raise
        transaction = _GuardDeploymentTransaction(
            session=session,
            install=install,
            unit=unit,
            upload=opts.upload,
            remote_bin=remote_bin,
            staged_bin=staged_bin,
            previous_guard_alive=previous_guard.alive,
            previous_config_arg=(
                f" --config {sh_quote(remote_cfg)}" if previous_config_exists else ""
            ),
            previous_env_file=remote_env if previous_env_exists else None,
            lock=lock,
        )
        pid = ""
        try:
            # Snapshot the old executable before SFTP. The publication carries
            # an explicit absent marker, so rollback is correct even when an SSH
            # response is lost after the remote command actually completed.
            transaction.file_publications.append(
                _prepare_remote_file_publication(session, remote_bin, mode="700", lock=lock)
            )
            session.upload(binary, staged_bin)
            _verify_upload(session, binary, staged_bin, lock=lock)

            config_arg = ""
            if opts.intel is not None:
                _install_local_remote_file(
                    session,
                    opts.intel,
                    remote_intel,
                    mode="600",
                    publication_out=transaction.file_publications,
                    lock=lock,
                )
            if opts.malware_signatures is not None:
                _install_local_remote_file(
                    session,
                    opts.malware_signatures,
                    remote_signatures,
                    mode="600",
                    publication_out=transaction.file_publications,
                    lock=lock,
                )
            if opts.config is not None:
                _install_local_remote_file(
                    session,
                    opts.config,
                    remote_cfg,
                    mode="600",
                    publication_out=transaction.file_publications,
                    lock=lock,
                )
                config_arg = f" --config {sh_quote(remote_cfg)}"

            env_file = _install_guard_env(
                session,
                install,
                opts.api_token,
                opts.certificate_bundle,
                transaction.identity_publications,
                transaction.file_publications,
                lock,
            )

            # Set this before exec: the command may stop/publish/start remotely
            # and only then lose its SSH response.
            transaction.start_attempted = True
            run = session.exec(
                _guard_start_command(
                    remote_bin,
                    install,
                    unit,
                    config_arg,
                    opts.upload,
                    env_file,
                    staged_bin,
                    transaction.file_publications[0],
                    lock,
                )
            )
            pid = _parse_marked_pid(run.stdout)
            unit_started = _GUARD_UNIT_MARKER in run.stdout
            if not pid and not unit_started:
                raise RuntimeError(
                    f"failed to start guard daemon on {opts.target}\n"
                    f"stdout: {run.stdout.strip()}\nstderr: {run.stderr.strip()}"
                )
            if unit_started and not pid:
                pid = _systemd_unit_pid(session, unit, lock=lock)
            live_status = _guard_status_over(session, unit, install, lock=lock)
            if live_status.alive:
                pid = pid or live_status.pid or ""
            if not live_status.alive or not pid:
                raise RuntimeError(
                    f"guard daemon exited before activation on {opts.target}: {live_status.detail}"
                )

            manifest = _build_guard_deployment_manifest(
                identity_generation=identity_generation,
                binary_sha256=binary_sha256,
                config_sha256=config_sha256,
                pid=pid,
                unit=unit,
                remote_bin=remote_bin,
                remote_cfg=remote_cfg if opts.config is not None else None,
            )
            _install_guard_deployment_manifest(
                session,
                install,
                manifest,
                transaction.file_publications,
                lock=lock,
            )

            if opts.activation_callback is not None:
                opts.activation_callback()
            transaction.committed = True
        except BaseException as exc:
            rollback_confirmed = transaction.rollback()
            if isinstance(exc, Exception) and (
                not rollback_confirmed or isinstance(exc, _RemoteRollbackUncertainError)
            ):
                raise GuardDeploymentUncertainError(
                    target=opts.target,
                    deployment_id=expected_manifest.deployment_id,
                    identity_generation=identity_generation,
                ) from exc
            raise
        else:
            transaction.commit()
        finally:
            _release_guard_deployment_lock(session, lock)

    return pid or ""


_MAX_IDENTITY_PEM_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, repr=False)
class _ValidatedAgentCertificateBundle:
    certificate_pem: bytes
    private_key_pem: bytes
    ca_certificate_pem: bytes


@dataclass(frozen=True)
class _AgentIdentityPublication:
    """Remote pointer switch retained until central activation commits."""

    previous_link: str
    absent_marker: str
    had_previous: bool


@dataclass(frozen=True)
class _RemoteFilePublication:
    """One atomically replaced remote file with a retained previous copy."""

    path: str
    previous_path: str
    previous_tmp_path: str
    absent_marker: str
    mode: str
    had_previous: bool


@dataclass(frozen=True)
class _GuardDeploymentLock:
    path: str
    owner: str
    ttl_seconds: int

    @property
    def gate_path(self) -> str:
        """Stable inode used to serialize lease metadata and fenced commands.

        It deliberately lives beside the install directory rather than inside
        it, so a conditional uninstall cannot unlink the inode while a command
        still holds the kernel lock.
        """

        return f"{PurePosixPath(self.path).parent}.deployment-lock-gate"


@dataclass
class _GuardDeploymentTransaction:
    """All remote state retained until central Agent activation commits."""

    session: SshSession
    install: str
    unit: str
    upload: str
    remote_bin: str
    staged_bin: str
    previous_guard_alive: bool
    previous_config_arg: str
    previous_env_file: str | None
    lock: _GuardDeploymentLock
    file_publications: list[_RemoteFilePublication] = field(default_factory=list)
    identity_publications: list[_AgentIdentityPublication] = field(default_factory=list)
    start_attempted: bool = False
    committed: bool = False

    def rollback(self) -> bool:
        """Best-effort full rollback; return whether the old outcome is proven."""

        if self.committed:
            return True
        try:
            if not _guard_deployment_lock_owned(self.session, self.lock):
                logger.warning("Guard rollback fenced out by a newer deployment owner")
                return False
        except Exception as exc:  # noqa: BLE001 - inability to fence is uncertain
            logger.warning("failed to verify Guard rollback fence: %s", exc)
            return False
        confirmed = True

        def attempt(operation: Callable[[], object]) -> None:
            nonlocal confirmed
            try:
                operation()
            except Exception as exc:  # noqa: BLE001 - keep attempting every rollback step
                confirmed = False
                logger.warning("Guard deployment rollback step failed: %s", exc)

        if self.start_attempted:
            attempt(lambda: _quiesce_guard(self.session, self.install, self.unit, lock=self.lock))
        for publication in reversed(self.file_publications):
            attempt(
                lambda publication=publication: _rollback_remote_file(
                    self.session, publication, lock=self.lock
                )
            )
        for publication in reversed(self.identity_publications):
            attempt(
                lambda publication=publication: _rollback_agent_identity(
                    self.session, publication, lock=self.lock
                )
            )
        attempt(lambda: self.session.exec(f"rm -f {sh_quote(self.staged_bin)}"))
        if not self.start_attempted:
            return confirmed
        attempt(
            lambda: _restore_guard_after_failed_deploy(
                self.session,
                self.remote_bin,
                self.install,
                self.unit,
                self.previous_config_arg,
                self.upload,
                self.previous_env_file,
                self.previous_guard_alive,
                lock=self.lock,
            )
        )
        try:
            restored = _guard_status_over(self.session, self.unit, self.install)
            if restored.alive != self.previous_guard_alive:
                confirmed = False
        except Exception as exc:  # noqa: BLE001 - inability to prove state is uncertain
            confirmed = False
            logger.warning("failed to verify Guard deployment rollback: %s", exc)
        return confirmed

    def commit(self) -> None:
        """Discard backups after activation; cleanup failure is recoverable litter."""

        for publication in self.identity_publications:
            try:
                _commit_agent_identity(self.session, publication, lock=self.lock)
            except Exception as exc:  # noqa: BLE001 - activation is already committed
                logger.warning("failed to clean committed Agent identity backup: %s", exc)
        for publication in self.file_publications:
            try:
                _commit_remote_file(self.session, publication, lock=self.lock)
            except Exception as exc:  # noqa: BLE001 - activation is already committed
                logger.warning("failed to clean committed Guard file backup: %s", exc)


def _require_remote_rollback(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except Exception as exc:  # noqa: BLE001 - convert to an explicit uncertain outcome
        raise _RemoteRollbackUncertainError(label) from exc


def _pem_bytes(value: str, field_name: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"AgentCertificateBundle.{field_name} must be non-empty")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"AgentCertificateBundle.{field_name} must be ASCII PEM") from exc
    if b"\x00" in encoded:
        raise ValueError(f"AgentCertificateBundle.{field_name} contains a NUL byte")
    if len(encoded) > _MAX_IDENTITY_PEM_BYTES:
        raise ValueError(
            f"AgentCertificateBundle.{field_name} exceeds {_MAX_IDENTITY_PEM_BYTES} bytes"
        )
    if field_name == "private_key_pem":
        private_key_begin = b"-----BEGIN " + b"PRIVATE KEY-----"
        private_key_end = b"-----END " + b"PRIVATE KEY-----"
        if (
            encoded.count(private_key_begin) != 1
            or encoded.count(private_key_end) != 1
            or b"-----BEGIN CERTIFICATE-----" in encoded
        ):
            raise ValueError(
                "AgentCertificateBundle.private_key_pem must contain one PKCS#8 private key"
            )
    elif (
        encoded.count(b"-----BEGIN CERTIFICATE-----") != 1
        or encoded.count(b"-----END CERTIFICATE-----") != 1
        or b"PRIVATE KEY" in encoded
    ):
        raise ValueError(f"AgentCertificateBundle.{field_name} must contain one certificate")
    return encoded


def _public_key_der(public_key: object) -> bytes:
    try:
        return public_key.public_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("AgentCertificateBundle contains an unsupported public key") from exc


def _validate_agent_certificate_bundle(
    bundle: AgentCertificateBundle,
) -> _ValidatedAgentCertificateBundle:
    """Fail closed before any SSH mutation when deployment material is inconsistent."""
    if not isinstance(bundle, AgentCertificateBundle):
        raise TypeError("certificate_bundle must be an AgentCertificateBundle")
    if bundle.identity.state is not AgentIdentityState.ACTIVE:
        raise ValueError("cannot deploy a certificate for a non-active Agent identity")
    if bundle.certificate.state not in {
        AgentCertificateState.STAGED,
        AgentCertificateState.ACTIVE,
    }:
        raise ValueError("Agent certificate must be staged or active for deployment")
    if bundle.certificate.agent_id != bundle.identity.agent_id:
        raise ValueError("Agent certificate belongs to a different identity")
    if not any(
        item.generation == bundle.certificate.generation
        and item.serial_number == bundle.certificate.serial_number
        for item in bundle.identity.certificates
    ):
        raise ValueError("Agent certificate is absent from its identity generation history")

    certificate_pem = _pem_bytes(bundle.certificate_pem, "certificate_pem")
    private_key_pem = _pem_bytes(bundle.private_key_pem, "private_key_pem")
    ca_certificate_pem = _pem_bytes(bundle.ca_certificate_pem, "ca_certificate_pem")
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
    except ValueError as exc:
        raise ValueError("AgentCertificateBundle.certificate_pem is invalid") from exc
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("AgentCertificateBundle.private_key_pem is invalid or encrypted") from exc
    try:
        ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem)
    except ValueError as exc:
        raise ValueError("AgentCertificateBundle.ca_certificate_pem is invalid") from exc

    serial_number = format(certificate.serial_number, "x")
    if serial_number != bundle.certificate.serial_number:
        raise ValueError("Agent certificate serial number does not match bundle metadata")
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    if hashlib.sha256(certificate_der).hexdigest() != bundle.certificate.cert_sha256:
        raise ValueError("Agent certificate fingerprint does not match bundle metadata")
    certificate_spki = _public_key_der(certificate.public_key())
    if hashlib.sha256(certificate_spki).hexdigest() != bundle.certificate.spki_sha256:
        raise ValueError("Agent certificate public key does not match bundle metadata")
    if _public_key_der(private_key.public_key()) != certificate_spki:  # type: ignore[attr-defined]
        raise ValueError("Agent certificate and private key do not match")

    try:
        leaf_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        extended_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ca_constraints = ca_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("Agent certificate bundle is missing required X.509 extensions") from exc
    if leaf_constraints.ca:
        raise ValueError("Agent leaf certificate must not be a CA")
    if ExtendedKeyUsageOID.CLIENT_AUTH not in extended_usage:
        raise ValueError("Agent leaf certificate lacks the clientAuth extended key usage")
    if not ca_constraints.ca:
        raise ValueError("Agent CA certificate lacks CA basic constraints")
    if certificate.issuer != ca_certificate.subject:
        raise ValueError("Agent leaf certificate was not issued by the supplied CA")
    ca_public_key = ca_certificate.public_key()
    if not isinstance(ca_public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Agent CA uses an unsupported public-key algorithm")
    try:
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
    except InvalidSignature as exc:
        raise ValueError("Agent leaf certificate signature does not match the supplied CA") from exc

    return _ValidatedAgentCertificateBundle(
        certificate_pem=certificate_pem,
        private_key_pem=private_key_pem,
        ca_certificate_pem=ca_certificate_pem,
    )


def _upload_private_bytes(
    session: SshSession,
    payload: bytes,
    remote_path: str,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> None:
    """Stream one private payload over SFTP; never persist it locally or put it in argv."""

    if lock is not None:
        _renew_guard_deployment_lock(session, lock)
    session.upload_bytes(payload, remote_path)


def _install_agent_identity(
    session: SshSession,
    bundle: AgentCertificateBundle,
    lock: _GuardDeploymentLock | None = None,
) -> tuple[str, str, str, _AgentIdentityPublication]:
    """Stage a complete mTLS generation and atomically publish stable paths."""
    material = _validate_agent_certificate_bundle(bundle)
    generation_id = short_id()
    generation_name = agent_identity_generation_name(
        bundle.certificate.generation,
        bundle.certificate.cert_sha256,
    )
    staging_dir = f"{AGENT_IDENTITY_DIR}/.staging-{generation_id}"
    generation_dir = f"{AGENT_IDENTITY_DIR}/{generation_name}"
    current_link_tmp = f"{AGENT_IDENTITY_DIR}/.current-{generation_id}"
    previous_link = f"{AGENT_IDENTITY_DIR}/.previous-{generation_id}"
    absent_marker = f"{AGENT_IDENTITY_DIR}/.absent-{generation_id}"
    q_identity = sh_quote(AGENT_IDENTITY_DIR)
    q_staging = sh_quote(staging_dir)

    q_current = sh_quote(AGENT_IDENTITY_CURRENT)
    q_previous = sh_quote(previous_link)
    q_absent = sh_quote(absent_marker)
    provisional_publication = _AgentIdentityPublication(
        previous_link=previous_link,
        absent_marker=absent_marker,
        had_previous=False,
    )
    try:
        prepared = session.exec(
            f"{_guard_lock_fence(lock)}"
            f"[ ! -L {q_identity} ] && mkdir -p {q_identity} && "
            f"[ -d {q_identity} ] && chmod 700 {q_identity} && "
            f"if [ -L {q_current} ]; then "
            f"  old=$(readlink {q_current}); "
            f'  case "$old" in generation-*) ln -s "$old" {q_previous} '
            f"&& echo __previous=1 ;; *) exit 42 ;; esac; "
            f"else : > {q_absent} && chmod 600 {q_absent} "
            f"&& echo __previous=0; fi && "
            f"mkdir {q_staging} && chmod 700 {q_staging} && echo __ok"
        )
    except BaseException:
        _require_remote_rollback(
            lambda: _rollback_agent_identity(session, provisional_publication, lock=lock),
            "could not prove Agent identity rollback after prepare failure",
        )
        raise
    if not prepared.success or "__ok" not in prepared.stdout:
        _require_remote_rollback(
            lambda: _rollback_agent_identity(session, provisional_publication, lock=lock),
            "could not prove Agent identity rollback after rejected prepare",
        )
        raise RuntimeError("failed to prepare private Agent identity directory")
    publication = _AgentIdentityPublication(
        previous_link=previous_link,
        absent_marker=absent_marker,
        had_previous="__previous=1" in prepared.stdout,
    )

    staged_paths = {
        "certificate": f"{staging_dir}/{_IDENTITY_FILE_NAMES['certificate']}",
        "private_key": f"{staging_dir}/{_IDENTITY_FILE_NAMES['private_key']}",
        "ca": f"{staging_dir}/{_IDENTITY_FILE_NAMES['ca']}",
    }
    try:
        _upload_private_bytes(
            session,
            material.certificate_pem,
            staged_paths["certificate"],
            lock=lock,
        )
        _upload_private_bytes(
            session,
            material.private_key_pem,
            staged_paths["private_key"],
            lock=lock,
        )
        _upload_private_bytes(
            session,
            material.ca_certificate_pem,
            staged_paths["ca"],
            lock=lock,
        )
    except BaseException:
        with contextlib.suppress(Exception):
            session.exec(f"rm -rf {q_staging}")
        _require_remote_rollback(
            lambda: _rollback_agent_identity(session, publication, lock=lock),
            "could not prove Agent identity rollback after SFTP failure",
        )
        raise

    q_staged_files = " ".join(sh_quote(path) for path in staged_paths.values())
    q_generation = sh_quote(generation_dir)
    q_link_tmp = sh_quote(current_link_tmp)
    try:
        published = session.exec(
            f"{_guard_lock_fence(lock)}chmod 600 {q_staged_files} && "
            f"mv {q_staging} {q_generation} && "
            f"ln -s {sh_quote(generation_name)} {q_link_tmp} && "
            f"mv -Tf {q_link_tmp} {q_current} && echo __ok"
        )
    except BaseException:
        _require_remote_rollback(
            lambda: _rollback_agent_identity(session, publication, lock=lock),
            "could not prove Agent identity rollback after publish response loss",
        )
        with contextlib.suppress(Exception):
            session.exec(f"rm -rf {q_staging} {q_link_tmp}")
        raise
    if not published.success or "__ok" not in published.stdout:
        # The rename may have succeeded even if its response was lost. Restore
        # the saved pointer before central Form aborts this generation.
        _require_remote_rollback(
            lambda: _rollback_agent_identity(session, publication, lock=lock),
            "could not prove Agent identity rollback after publish rejection",
        )
        with contextlib.suppress(Exception):
            session.exec(f"rm -rf {q_staging} {q_link_tmp}")
        raise RuntimeError("failed to atomically publish Agent certificate generation")
    return (
        AGENT_CERT_PATH,
        AGENT_KEY_PATH,
        AGENT_CA_PATH,
        publication,
    )


def agent_identity_generation_name(generation: int, cert_sha256: str) -> str:
    """Deterministic remote generation name used for crash reconciliation."""

    name = f"generation-{generation}-{cert_sha256[:16]}"
    if not _IDENTITY_GENERATION_NAME.fullmatch(name):
        raise ValueError("invalid Agent certificate generation metadata")
    return name


def _rollback_agent_identity(
    session: SshSession,
    publication: _AgentIdentityPublication,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> None:
    q_current = sh_quote(AGENT_IDENTITY_CURRENT)
    q_previous = sh_quote(publication.previous_link)
    q_absent = sh_quote(publication.absent_marker)
    command = (
        f"{_guard_lock_fence(lock)}"
        f"if [ -L {q_previous} ]; then mv -Tf {q_previous} {q_current}; "
        f"elif [ -f {q_absent} ]; then rm -f {q_current}; fi; "
        f"rm -f {q_previous} {q_absent} && echo __rolled_back"
    )
    result = session.exec(command)
    if not result.success or "__rolled_back" not in result.stdout:
        raise RuntimeError("failed to restore the previous Agent certificate generation")


def _commit_agent_identity(
    session: SshSession,
    publication: _AgentIdentityPublication,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> None:
    result = session.exec(
        f"{_guard_lock_fence(lock)}rm -f {sh_quote(publication.previous_link)} "
        f"{sh_quote(publication.absent_marker)} && echo __committed"
    )
    if not result.success:
        raise RuntimeError("failed to commit the Agent certificate pointer")


def _rollback_remote_file(
    session: SshSession,
    publication: _RemoteFilePublication,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> None:
    q_path = sh_quote(publication.path)
    q_previous = sh_quote(publication.previous_path)
    q_previous_tmp = sh_quote(publication.previous_tmp_path)
    q_absent = sh_quote(publication.absent_marker)
    command = (
        f"{_guard_lock_fence(lock)}"
        f"if [ -f {q_previous} ]; then mv -f {q_previous} {q_path} "
        f"&& chmod {publication.mode} {q_path}; "
        f"elif [ -f {q_absent} ]; then rm -f {q_path}; fi; "
        f"rm -f {q_previous} {q_previous_tmp} {q_absent} && echo __rolled_back"
    )
    result = session.exec(command)
    if not result.success or "__rolled_back" not in result.stdout:
        raise RuntimeError(f"failed to restore previous remote file {publication.path}")


def _commit_remote_file(
    session: SshSession,
    publication: _RemoteFilePublication,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> None:
    result = session.exec(
        f"{_guard_lock_fence(lock)}rm -f {sh_quote(publication.previous_path)} "
        f"{sh_quote(publication.previous_tmp_path)} "
        f"{sh_quote(publication.absent_marker)} && echo __committed"
    )
    if not result.success or "__committed" not in result.stdout:
        raise RuntimeError(f"failed to commit remote file {publication.path}")


def _prepare_remote_file_publication(
    session: SshSession,
    remote_path: str,
    *,
    mode: str,
    lock: _GuardDeploymentLock | None = None,
) -> _RemoteFilePublication:
    """Snapshot a regular file with response-loss-safe present/absent state."""

    publication_id = short_id()
    publication = _RemoteFilePublication(
        path=remote_path,
        previous_path=f"{remote_path}.previous-{publication_id}",
        previous_tmp_path=f"{remote_path}.previous-{publication_id}.tmp",
        absent_marker=f"{remote_path}.absent-{publication_id}",
        mode=mode,
        had_previous=False,
    )
    q_path = sh_quote(publication.path)
    q_previous = sh_quote(publication.previous_path)
    q_previous_tmp = sh_quote(publication.previous_tmp_path)
    q_absent = sh_quote(publication.absent_marker)
    try:
        prepared = session.exec(
            f"{_guard_lock_fence(lock)}if [ -L {q_path} ]; then exit 42; "
            f"elif [ -f {q_path} ]; then cp -p {q_path} {q_previous_tmp} "
            f"&& chmod {mode} {q_previous_tmp} && mv -f {q_previous_tmp} {q_previous} "
            f"&& echo __previous=1; "
            f"elif [ -e {q_path} ]; then exit 43; "
            f"else : > {q_absent} && chmod 600 {q_absent} && echo __previous=0; fi; "
            f"echo __prepared"
        )
    except BaseException:
        _require_remote_rollback(
            lambda: _rollback_remote_file(session, publication, lock=lock),
            f"could not prove rollback after preserving {remote_path}",
        )
        raise
    if not prepared.success or "__prepared" not in prepared.stdout:
        _require_remote_rollback(
            lambda: _rollback_remote_file(session, publication, lock=lock),
            f"could not prove rollback after rejected preserve of {remote_path}",
        )
        raise RuntimeError(f"failed to preserve previous remote file {remote_path}")
    return _RemoteFilePublication(
        path=publication.path,
        previous_path=publication.previous_path,
        previous_tmp_path=publication.previous_tmp_path,
        absent_marker=publication.absent_marker,
        mode=publication.mode,
        had_previous="__previous=1" in prepared.stdout,
    )


def _remote_file_cas_condition(publication: _RemoteFilePublication) -> str:
    """Shell predicate proving the published path still matches our snapshot."""

    q_path = sh_quote(publication.path)
    q_previous = sh_quote(publication.previous_path)
    q_absent = sh_quote(publication.absent_marker)
    return (
        f"if [ -f {q_previous} ]; then cmp -s {q_previous} {q_path}; "
        f"elif [ -f {q_absent} ]; then [ ! -e {q_path} ]; else false; fi"
    )


def _publish_remote_file(
    session: SshSession,
    publication: _RemoteFilePublication,
    remote_tmp: str,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> None:
    q_path = sh_quote(publication.path)
    q_tmp = sh_quote(remote_tmp)
    published = session.exec(
        f"{_guard_lock_fence(lock)}{_remote_file_cas_condition(publication)} && "
        f"chmod {publication.mode} {q_tmp} && mv -f {q_tmp} {q_path} "
        f"&& chmod {publication.mode} {q_path} && echo __ok"
    )
    if not published.success or "__ok" not in published.stdout:
        raise RuntimeError(f"failed to atomically publish remote file {publication.path}")


def _install_remote_bytes_file(
    session: SshSession,
    content: bytes,
    remote_path: str,
    *,
    mode: str,
    publication_out: list[_RemoteFilePublication] | None = None,
    lock: _GuardDeploymentLock | None = None,
) -> str:
    publication = _prepare_remote_file_publication(session, remote_path, mode=mode, lock=lock)
    remote_tmp = f"{remote_path}.tmp-{short_id()}"
    try:
        _upload_private_bytes(session, content, remote_tmp, lock=lock)
        _publish_remote_file(session, publication, remote_tmp, lock=lock)
    except BaseException:
        _require_remote_rollback(
            lambda: _rollback_remote_file(session, publication, lock=lock),
            f"could not prove rollback of {remote_path}",
        )
        with contextlib.suppress(Exception):
            session.exec(f"rm -f {sh_quote(remote_tmp)}")
        raise
    if publication_out is None:
        _commit_remote_file(session, publication, lock=lock)
    else:
        publication_out.append(publication)
    return remote_path


def _install_local_remote_file(
    session: SshSession,
    local_path: Path,
    remote_path: str,
    *,
    mode: str,
    publication_out: list[_RemoteFilePublication],
    lock: _GuardDeploymentLock | None = None,
) -> str:
    publication = _prepare_remote_file_publication(session, remote_path, mode=mode, lock=lock)
    remote_tmp = f"{remote_path}.tmp-{short_id()}"
    try:
        session.upload(local_path, remote_tmp)
        _verify_upload(session, local_path, remote_tmp, lock=lock)
        _publish_remote_file(session, publication, remote_tmp, lock=lock)
    except BaseException:
        _require_remote_rollback(
            lambda: _rollback_remote_file(session, publication, lock=lock),
            f"could not prove rollback of {remote_path}",
        )
        with contextlib.suppress(Exception):
            session.exec(f"rm -f {sh_quote(remote_tmp)}")
        raise
    publication_out.append(publication)
    return remote_path


def _install_env_file(
    session: SshSession,
    install: str,
    content: bytes,
    publication_out: list[_RemoteFilePublication] | None = None,
    lock: _GuardDeploymentLock | None = None,
) -> str:
    """Atomically publish the 0600 systemd/shell EnvironmentFile."""
    remote_env = f"{install}/agentd.env"
    return _install_remote_bytes_file(
        session,
        content,
        remote_env,
        mode="600",
        publication_out=publication_out,
        lock=lock,
    )


def _install_guard_env(
    session: SshSession,
    install: str,
    api_token: str | None,
    certificate_bundle: AgentCertificateBundle | None = None,
    publication_out: list[_AgentIdentityPublication] | None = None,
    env_publication_out: list[_RemoteFilePublication] | None = None,
    lock: _GuardDeploymentLock | None = None,
) -> str | None:
    """Install Guard authentication without exposing credentials in argv or logs.

    A per-Agent certificate bundle takes precedence and publishes only stable
    ``FORM_AGENT_CERT/KEY/CA`` paths. The legacy token path remains available for
    migration, but an explicitly unsafe token now fails closed instead of
    silently starting an unauthenticated daemon.
    """
    if certificate_bundle is not None:
        cert_path, key_path, ca_path, publication = _install_agent_identity(
            session, certificate_bundle, lock=lock
        )
        content = (
            f"FORM_AGENT_CERT={cert_path}\nFORM_AGENT_KEY={key_path}\nFORM_AGENT_CA={ca_path}\n"
        ).encode("ascii")
        try:
            installed = _install_env_file(
                session,
                install,
                content,
                env_publication_out,
                lock,
            )
        except BaseException:
            _require_remote_rollback(
                lambda: _rollback_agent_identity(session, publication, lock=lock),
                "could not prove Agent identity rollback after env failure",
            )
            raise
        if publication_out is None:
            _commit_agent_identity(session, publication)
        else:
            publication_out.append(publication)
        return installed

    token = _legacy_ingest_token(api_token)
    if token is None:
        return None
    return _install_env_file(
        session,
        install,
        f"FORM_INGEST_TOKEN={token}\n".encode("ascii"),
        env_publication_out,
        lock,
    )


def _guard_lock_gate(lock: _GuardDeploymentLock) -> str:
    """Hold one stable kernel lock for the rest of the remote shell command."""

    q_gate = sh_quote(lock.gate_path)
    return (
        "umask 077; command -v flock >/dev/null 2>&1 || exit 77; "
        f"[ ! -L {q_gate} ] || exit 77; "
        f"exec 9>>{q_gate} || exit 77; "
        f"[ -f {q_gate} ] && [ ! -L {q_gate} ] || exit 77; "
        f"chmod 600 {q_gate} || exit 77; "
        "flock -x -n 9 || exit 76; "
    )


def _acquire_guard_deployment_lock(
    session: SshSession,
    install: str,
) -> _GuardDeploymentLock:
    """Acquire a remote lease whose mutations are serialized by ``flock``."""

    operation_timeout = remote_command_timeout_seconds()
    if not math.isfinite(operation_timeout) or operation_timeout <= 0:
        operation_timeout = 30 * 60
    # Each exec/SFTP operation has this wall-clock bound. The extra minute
    # closes scheduling and round-trip gaps before the next owner renewal.
    ttl_seconds = max(60, math.ceil(operation_timeout) + 60)
    lock = _GuardDeploymentLock(
        path=f"{install}/.deployment-lock",
        owner=f"{short_id()}{short_id()}",
        ttl_seconds=ttl_seconds,
    )
    q_lock = sh_quote(lock.path)
    q_owner = sh_quote(f"{lock.path}/owner")
    q_expires = sh_quote(f"{lock.path}/expires")
    command = (
        f"{_guard_lock_gate(lock)}"
        "now=$(date +%s) || exit 70; "
        f"if [ -e {q_lock} ] || [ -L {q_lock} ]; then "
        f"  expiry=$(cat {q_expires} 2>/dev/null || true); "
        "  case \"$expiry\" in ''|*[!0-9]*) ;; "
        '    *) [ "$expiry" -le "$now" ] || exit 73 ;; esac; '
        f"  rm -rf {q_lock} || exit 73; "
        "fi; "
        f"mkdir {q_lock} || exit 73; "
        f"printf '%s\n' {sh_quote(lock.owner)} > {q_owner} && "
        f"printf '%s\n' $((now + {lock.ttl_seconds})) > {q_expires} && "
        f"chmod 700 {q_lock} && chmod 600 {q_owner} {q_expires} && echo __locked"
    )
    try:
        result = session.exec(command)
    except BaseException:
        _release_guard_deployment_lock(session, lock)
        raise
    if not result.success or "__locked" not in result.stdout:
        _release_guard_deployment_lock(session, lock)
        if result.status == 77:
            raise RuntimeError(
                "safe Guard deployment locking requires a regular gate file and util-linux flock"
            )
        raise RuntimeError(f"another Guard deployment is active for {session.target}")
    return lock


def _guard_lock_fence(lock: _GuardDeploymentLock | None) -> str:
    if lock is None:
        return ""
    q_owner = sh_quote(f"{lock.path}/owner")
    q_expires = sh_quote(f"{lock.path}/expires")
    return (
        f"{_guard_lock_gate(lock)}"
        "now=$(date +%s) || exit 70; "
        f"owner=$(cat {q_owner} 2>/dev/null || true); "
        f"expiry=$(cat {q_expires} 2>/dev/null || true); "
        "case \"$expiry\" in ''|*[!0-9]*) exit 74 ;; esac; "
        f'[ "$owner" = {sh_quote(lock.owner)} ] && '
        '[ "$expiry" -gt "$now" ] || exit 74; '
        f"printf '%s\n' $((now + {lock.ttl_seconds})) > "
        f"{q_expires} || exit 75; "
    )


def _renew_guard_deployment_lock(
    session: SshSession,
    lock: _GuardDeploymentLock,
) -> None:
    result = session.exec(f"{_guard_lock_fence(lock)}echo __renewed")
    if not result.success or "__renewed" not in result.stdout:
        raise RuntimeError("Guard deployment lock renewal was fenced out")


def _guard_deployment_lock_owned(
    session: SshSession,
    lock: _GuardDeploymentLock,
) -> bool:
    result = session.exec(f"{_guard_lock_fence(lock)}echo __owner")
    return result.success and "__owner" in result.stdout


def _release_guard_deployment_lock(
    session: SshSession,
    lock: _GuardDeploymentLock,
) -> None:
    q_lock = sh_quote(lock.path)
    q_owner = sh_quote(f"{lock.path}/owner")
    try:
        session.exec(
            f"{_guard_lock_gate(lock)}if [ -d {q_lock} ] && "
            f'[ "$(cat {q_owner} 2>/dev/null)" = '
            f"{sh_quote(lock.owner)} ]; then rm -rf {q_lock}; fi; echo __released"
        )
    except Exception as exc:  # noqa: BLE001 - lease expires and must not mask deploy result
        logger.warning("failed to release remote Guard deployment lock: %s", exc)


def _build_guard_deployment_manifest(
    *,
    identity_generation: str | None,
    binary_sha256: str,
    config_sha256: str | None,
    pid: str,
    unit: str,
    remote_bin: str,
    remote_cfg: str | None,
) -> GuardDeploymentManifest:
    desired = {
        "identity_generation": identity_generation,
        "binary_sha256": binary_sha256,
        "config_sha256": config_sha256,
        "unit_name": unit,
        "binary_path": remote_bin,
        "config_path": remote_cfg,
    }
    deployment_id = hashlib.sha256(
        json.dumps(desired, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:32]
    return GuardDeploymentManifest(
        deployment_id=deployment_id,
        identity_generation=identity_generation,
        binary_sha256=binary_sha256,
        config_sha256=config_sha256,
        pid=pid,
        unit_name=unit,
        binary_path=remote_bin,
        config_path=remote_cfg,
    )


def _guard_manifest_bytes(manifest: GuardDeploymentManifest) -> bytes:
    payload = {
        "version": _GUARD_MANIFEST_VERSION,
        "deployment_id": manifest.deployment_id,
        "identity_generation": manifest.identity_generation,
        "binary_sha256": manifest.binary_sha256,
        "config_sha256": manifest.config_sha256,
        "pid": manifest.pid,
        "unit_name": manifest.unit_name,
        "binary_path": manifest.binary_path,
        "config_path": manifest.config_path,
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _install_guard_deployment_manifest(
    session: SshSession,
    install: str,
    manifest: GuardDeploymentManifest,
    publication_out: list[_RemoteFilePublication],
    *,
    lock: _GuardDeploymentLock | None = None,
) -> str:
    return _install_remote_bytes_file(
        session,
        _guard_manifest_bytes(manifest),
        f"{install}/{GUARD_DEPLOYMENT_MANIFEST_NAME}",
        mode="600",
        publication_out=publication_out,
        lock=lock,
    )


def _guard_start_command(
    remote_bin: str,
    install: str,
    unit: str,
    config_arg: str,
    upload: str,
    env_file: str | None = None,
    staged_bin: str | None = None,
    binary_publication: _RemoteFilePublication | None = None,
    lock: _GuardDeploymentLock | None = None,
) -> str:
    """Build an idempotent remote restart command: systemd-run or setsid.

    A redeploy restarts an existing daemon so migration from the legacy bearer
    environment to mTLS (and later configuration changes) takes effect. The
    systemd branch stops/resets the deterministic transient unit before creating
    it again; the fallback terminates only this install directory's old process
    before starting the detached replacement. Every operator-controlled value is
    ``sh_quote``-escaped; the unit name is validated by the caller.

    When ``env_file`` is given, authentication configuration is fed to the
    daemon's environment — via ``EnvironmentFile=`` for systemd (a transient
    unit starts with a clean env) and by sourcing the file for the setsid
    fallback. The file contains either the legacy bearer or stable mTLS paths;
    neither bearer nor PEM content enters argv.
    """
    q_bin = sh_quote(remote_bin)
    q_staged_bin = sh_quote(staged_bin) if staged_bin else q_bin
    q_log = sh_quote(f"{install}/guard.log")
    q_ready = sh_quote(f"{install}/{GUARD_READY_FILE_NAME}")
    q_upload = sh_quote(upload)
    q_unit = sh_quote(unit)
    q_env = sh_quote(env_file) if env_file else None
    # `respond --upload <form>` — only the umbrella uploads. config_arg is
    # already quoted (or empty). (`guard` remains a clap alias of `respond`.)
    guard_args = f"respond{config_arg} --ready-file {q_ready} --upload {q_upload}"
    binary_cas = (
        f"{_remote_file_cas_condition(binary_publication)} && "
        if binary_publication is not None
        else ""
    )
    publish_binary = (
        f"{binary_cas}chmod +x {q_staged_bin} && mv -f {q_staged_bin} {q_bin} "
        f"&& chmod +x {q_bin} && "
        if staged_bin
        else f"chmod +x {q_bin} && "
    )
    systemd_env = f"--property=EnvironmentFile={q_env} " if q_env else ""
    # `systemd-run` returning only proves that a process was accepted. Wait for
    # agentd to publish the PID-bound marker after every configured sensor has
    # passed preflight and survived startup; otherwise the deployment rolls back.
    systemd_ready_wait = (
        f'i=0; pid=; ready=; while [ "$i" -lt 30 ]; do '
        f"pid=$(systemctl show -p MainPID --value {q_unit} 2>/dev/null); "
        f"if [ -f {q_ready} ] && [ ! -L {q_ready} ]; then "
        f"ready=$(cat {q_ready} 2>/dev/null); else ready=; fi; "
        f'if [ -n "$pid" ] && [ "$pid" != 0 ] && [ "$ready" = "$pid" ]; then '
        f"echo {_GUARD_UNIT_MARKER}{q_unit}; echo {_GUARD_PID_MARKER}$pid; break; fi; "
        "i=$((i + 1)); sleep 0.5; done; "
        '[ -n "$pid" ] && [ "$pid" != 0 ] && [ "$ready" = "$pid" ]'
    )
    systemd = (
        f"systemctl stop {q_unit} >/dev/null 2>&1 || true; "
        f"systemctl reset-failed {q_unit} >/dev/null 2>&1 || true; "
        f"{publish_binary}"
        f"rm -f {q_ready} && "
        f"systemd-run --unit={q_unit} --collect "
        f"--property=Restart=on-failure --property=RestartSec=5 "
        f"{systemd_env}"
        f"-- {q_bin} {guard_args} && {{ {systemd_ready_wait}; }}"
    )
    # setsid inherits the shell env, so source the 0600 file first (keeps the
    # token out of argv); `set -a` exports the assignments to the child.
    setsid_env = f"set -a; . {q_env}; set +a; " if q_env else ""
    kill_respond = sh_quote(_bracket_first(f"{install}/agentd respond"))
    kill_guard = sh_quote(_bracket_first(f"{install}/agentd guard"))
    setsid_ready_wait = (
        f'pid=$!; i=0; ready=; while [ "$i" -lt 30 ]; do '
        f"if [ -f {q_ready} ] && [ ! -L {q_ready} ]; then "
        f"ready=$(cat {q_ready} 2>/dev/null); else ready=; fi; "
        f'if kill -0 "$pid" 2>/dev/null && [ "$ready" = "$pid" ]; then '
        f"echo {_GUARD_PID_MARKER}$pid; break; fi; "
        'if ! kill -0 "$pid" 2>/dev/null; then break; fi; '
        "i=$((i + 1)); sleep 0.5; done; "
        'if ! kill -0 "$pid" 2>/dev/null || [ "$ready" != "$pid" ]; then '
        'kill "$pid" >/dev/null 2>&1 || true; exit 70; fi'
    )
    setsid = (
        f"pkill -f {kill_respond} >/dev/null 2>&1 || true; "
        f"pkill -f {kill_guard} >/dev/null 2>&1 || true; "
        f"{publish_binary}"
        f"rm -f {q_ready} && "
        f"{{ {setsid_env}setsid {q_bin} {guard_args} "
        f"> {q_log} 2>&1 < /dev/null & {setsid_ready_wait}; }}"
    )
    return (
        f"{_guard_lock_fence(lock)}"
        f"if command -v systemd-run >/dev/null 2>&1; then {systemd}; else {setsid}; fi"
    )


def _restore_guard_after_failed_deploy(
    session: SshSession,
    remote_bin: str,
    install: str,
    unit: str,
    config_arg: str,
    upload: str,
    env_file: str | None,
    previous_guard_alive: bool,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> None:
    """Best-effort restart of the previous auth/config after a failed commit."""

    if previous_guard_alive:
        result = session.exec(
            _guard_start_command(
                remote_bin,
                install,
                unit,
                config_arg,
                upload,
                env_file,
                lock=lock,
            )
        )
        if _GUARD_UNIT_MARKER not in result.stdout and not _parse_marked_pid(result.stdout):
            raise RuntimeError("failed to restart previous guard after deployment rollback")
        return

    _quiesce_guard(session, install, unit, lock=lock)


def _quiesce_guard(
    session: SshSession,
    install: str,
    unit: str,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> None:
    """Stop either supervisor form before restoring a previous deployment."""

    q_unit = sh_quote(unit)
    q_ready = sh_quote(f"{install}/{GUARD_READY_FILE_NAME}")
    kill_respond = sh_quote(_bracket_first(f"{install}/agentd respond"))
    kill_guard = sh_quote(_bracket_first(f"{install}/agentd guard"))
    result = session.exec(
        f"{_guard_lock_fence(lock)}if command -v systemctl >/dev/null 2>&1; then "
        f"systemctl stop {q_unit} >/dev/null 2>&1; "
        f"systemctl reset-failed {q_unit} >/dev/null 2>&1; fi; "
        f"pkill -f {kill_respond} >/dev/null 2>&1; "
        f"pkill -f {kill_guard} >/dev/null 2>&1; "
        f"rm -f {q_ready}; true"
    )
    if not result.success:
        raise RuntimeError("failed to quiesce guard after deployment rollback")


def _systemd_unit_pid(
    session: SshSession,
    unit: str,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> str:
    """Best-effort MainPID of a systemd unit (empty string when unknown)."""
    out = session.exec(
        f"{_guard_lock_fence(lock)}systemctl show -p MainPID --value {sh_quote(unit)} 2>/dev/null"
    )
    if not out.success:
        raise RuntimeError("failed to inspect Guard systemd PID")
    value = out.stdout.strip().splitlines()
    pid = value[-1].strip() if value else ""
    return pid if pid.isdigit() and pid != "0" else ""


@dataclass
class GuardStatus:
    """Liveness of a host's guard daemon (B5 probe result)."""

    alive: bool
    supervisor: str  # "systemd" | "process" | "unknown"
    detail: str = ""
    pid: str | None = None


@dataclass(frozen=True)
class GuardDeploymentProof:
    """One remote-lock-consistent manifest/liveness observation."""

    manifest: GuardDeploymentManifest | None
    status: GuardStatus


def guard_identity_generation(
    target: str,
    port: int = 22,
    identity: Path | None = None,
    password: str | None = None,
) -> str | None:
    """Read the server-owned remote ``current`` generation, never a payload claim."""

    key = bootstrap.ensure_key_auth(target, port, identity, password)
    user, host = split_user_host(target)
    with SshSession(host=host, user=user, key_path=key, port=port) as session:
        return _guard_identity_generation_over(session)


def _guard_identity_generation_over(
    session: SshSession,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> str | None:
    result = session.exec(
        f"{_guard_lock_fence(lock)}"
        f"if [ -L {sh_quote(AGENT_IDENTITY_CURRENT)} ]; then "
        f"readlink {sh_quote(AGENT_IDENTITY_CURRENT)}; fi"
    )
    if not result.success:
        raise RuntimeError("failed to inspect remote Agent certificate generation")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    generation = lines[-1]
    if not _IDENTITY_GENERATION_NAME.fullmatch(generation):
        raise RuntimeError("remote Agent certificate generation has an unsafe name")
    return generation


def guard_deployment_manifest(
    target: str,
    port: int = 22,
    identity: Path | None = None,
    password: str | None = None,
    install_dir: str = "/var/lib/agent-guard",
) -> GuardDeploymentManifest | None:
    """Read Form's durable proof of the exact remote Guard deployment."""

    install_dir = _validate_guard_install_dir(install_dir)
    key = bootstrap.ensure_key_auth(target, port, identity, password)
    user, host = split_user_host(target)
    with SshSession(host=host, user=user, key_path=key, port=port) as session:
        return _guard_deployment_manifest_over(session, install_dir)


def _guard_deployment_manifest_over(
    session: SshSession,
    install: str,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> GuardDeploymentManifest | None:
    path = f"{install}/{GUARD_DEPLOYMENT_MANIFEST_NAME}"
    q_path = sh_quote(path)
    result = session.exec(
        f"{_guard_lock_fence(lock)}"
        f"if [ -L {q_path} ] || {{ [ -e {q_path} ] && [ ! -f {q_path} ]; }}; then exit 42; "
        f"elif [ -f {q_path} ]; then size=$(wc -c < {q_path}) || exit 43; "
        f"[ \"$size\" -le 8192 ] || exit 44; printf '__manifest='; cat {q_path}; "
        "else echo __manifest_absent; fi"
    )
    if not result.success:
        raise RuntimeError("failed to read remote Guard deployment manifest")
    if "__manifest_absent" in result.stdout:
        return None
    marker = "__manifest="
    if marker not in result.stdout:
        raise RuntimeError("remote Guard deployment manifest response is malformed")
    raw = result.stdout.split(marker, 1)[1].strip()
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("remote Guard deployment manifest is invalid JSON") from exc
    expected_keys = {
        "version",
        "deployment_id",
        "identity_generation",
        "binary_sha256",
        "config_sha256",
        "pid",
        "unit_name",
        "binary_path",
        "config_path",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise RuntimeError("remote Guard deployment manifest has an invalid schema")
    identity_generation = payload["identity_generation"]
    config_sha256 = payload["config_sha256"]
    config_path = payload["config_path"]
    if (
        payload["version"] != _GUARD_MANIFEST_VERSION
        or not isinstance(payload["deployment_id"], str)
        or not _GUARD_DEPLOYMENT_ID.fullmatch(payload["deployment_id"])
        or (
            identity_generation is not None
            and (
                not isinstance(identity_generation, str)
                or not _IDENTITY_GENERATION_NAME.fullmatch(identity_generation)
            )
        )
        or not _is_sha256(payload["binary_sha256"])
        or (config_sha256 is not None and not _is_sha256(config_sha256))
        or not isinstance(payload["pid"], str)
        or not payload["pid"].isdigit()
        or payload["pid"] == "0"
        or not isinstance(payload["unit_name"], str)
        or payload["unit_name"] != _validate_unit_name(payload["unit_name"])
        or payload["binary_path"] != f"{install}/agentd"
        or config_path not in {None, f"{install}/guard.json"}
        or (config_sha256 is None) != (config_path is None)
    ):
        raise RuntimeError("remote Guard deployment manifest contains unsafe values")
    return GuardDeploymentManifest(
        deployment_id=payload["deployment_id"],
        identity_generation=identity_generation,
        binary_sha256=payload["binary_sha256"],
        config_sha256=config_sha256,
        pid=payload["pid"],
        unit_name=payload["unit_name"],
        binary_path=payload["binary_path"],
        config_path=config_path,
    )


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def guard_deployment_proof(
    target: str,
    port: int = 22,
    identity: Path | None = None,
    password: str | None = None,
    unit_name: str = "kcatta-guard",
    install_dir: str = "/var/lib/agent-guard",
) -> GuardDeploymentProof:
    """Observe manifest and liveness under one remote deployment lock.

    A systemd restart legitimately changes ``MainPID``. For an mTLS deployment
    only, the proof may refresh that PID after it proves the executable/config
    hashes, current certificate generation, unit, and ``/proc/<pid>/exe`` all
    still describe the manifest's deployment lineage. Legacy bearer manifests
    have no unique identity generation and therefore remain exact-PID only.
    """

    unit = _validate_unit_name(unit_name)
    install_dir = _validate_guard_install_dir(install_dir)
    key = bootstrap.ensure_key_auth(target, port, identity, password)
    user, host = split_user_host(target)
    with SshSession(host=host, user=user, key_path=key, port=port) as session:
        q_install = sh_quote(install_dir)
        state = session.exec(
            f"if [ -L {q_install} ] || "
            f"{{ [ -e {q_install} ] && [ ! -d {q_install} ]; }}; then exit 42; "
            f"elif [ -d {q_install} ]; then echo __guard_install_present; "
            "else echo __guard_install_absent; fi"
        )
        if not state.success:
            raise RuntimeError("remote Guard install directory is unsafe")
        if "__guard_install_absent" in state.stdout:
            return GuardDeploymentProof(
                manifest=None,
                status=_guard_status_over(session, unit, install_dir),
            )
        if "__guard_install_present" not in state.stdout:
            raise RuntimeError("remote Guard install directory response is malformed")
        lock = _acquire_guard_deployment_lock(session, install_dir)
        try:
            return _guard_deployment_proof_over(
                session,
                install_dir,
                unit,
                lock=lock,
            )
        finally:
            _release_guard_deployment_lock(session, lock)


def _guard_deployment_proof_over(
    session: SshSession,
    install: str,
    default_unit: str,
    *,
    lock: _GuardDeploymentLock,
) -> GuardDeploymentProof:
    manifest = _guard_deployment_manifest_over(session, install, lock=lock)
    unit = manifest.unit_name if manifest is not None else default_unit
    status = _guard_status_over(session, unit, install, lock=lock)
    if (
        manifest is None
        or not status.alive
        or status.pid is None
        or status.pid == manifest.pid
        or status.supervisor != "systemd"
        or manifest.identity_generation is None
    ):
        return GuardDeploymentProof(manifest=manifest, status=status)

    if not _guard_restart_lineage_matches(session, manifest, status.pid, lock=lock):
        return GuardDeploymentProof(manifest=manifest, status=status)

    refreshed = replace(manifest, pid=status.pid)
    _refresh_guard_manifest_pid_over(session, manifest, refreshed, lock=lock)
    return GuardDeploymentProof(manifest=refreshed, status=status)


def _guard_restart_lineage_matches(
    session: SshSession,
    manifest: GuardDeploymentManifest,
    live_pid: str,
    *,
    lock: _GuardDeploymentLock,
) -> bool:
    """Prove a changed systemd PID is a restart of this mTLS deployment."""

    if not live_pid.isdigit() or live_pid == "0" or manifest.identity_generation is None:
        return False
    q_binary = sh_quote(manifest.binary_path)
    q_binary_hash = sh_quote(manifest.binary_sha256)
    q_generation = sh_quote(manifest.identity_generation)
    q_current = sh_quote(AGENT_IDENTITY_CURRENT)
    config_check = ""
    if manifest.config_path is not None and manifest.config_sha256 is not None:
        q_config = sh_quote(manifest.config_path)
        q_config_hash = sh_quote(manifest.config_sha256)
        config_check = (
            f"[ -f {q_config} ] && [ ! -L {q_config} ] || exit 83; "
            f"config_hash=$(sha256sum {q_config} 2>/dev/null | awk '{{print $1}}'); "
            f'[ "$config_hash" = {q_config_hash} ] || exit 84; '
        )
    command = (
        f"{_guard_lock_fence(lock)}"
        f"[ -f {q_binary} ] && [ ! -L {q_binary} ] || exit 80; "
        f"binary_hash=$(sha256sum {q_binary} 2>/dev/null | awk '{{print $1}}'); "
        f'[ "$binary_hash" = {q_binary_hash} ] || exit 81; '
        f"{config_check}"
        f"[ -L {q_current} ] || exit 85; "
        f'[ "$(readlink {q_current})" = {q_generation} ] || exit 86; '
        f'[ "$(readlink -f /proc/{live_pid}/exe 2>/dev/null)" = {q_binary} ] '
        "|| exit 87; echo __guard_lineage"
    )
    result = session.exec(command)
    return result.success and "__guard_lineage" in result.stdout


def _refresh_guard_manifest_pid_over(
    session: SshSession,
    previous: GuardDeploymentManifest,
    refreshed: GuardDeploymentManifest,
    *,
    lock: _GuardDeploymentLock,
) -> None:
    """CAS-publish a proven systemd PID rollover without changing deployment id."""

    path = f"{lock.path.rsplit('/', 1)[0]}/{GUARD_DEPLOYMENT_MANIFEST_NAME}"
    temporary = f"{path}.pid-refresh-{short_id()}"
    previous_bytes = _guard_manifest_bytes(previous)
    expected_sha256 = hashlib.sha256(previous_bytes).hexdigest()
    _upload_private_bytes(
        session,
        _guard_manifest_bytes(refreshed),
        temporary,
        lock=lock,
    )
    q_path = sh_quote(path)
    q_temporary = sh_quote(temporary)
    try:
        result = session.exec(
            f"{_guard_lock_fence(lock)}"
            f"[ -f {q_path} ] && [ ! -L {q_path} ] || exit 88; "
            f"current_hash=$(sha256sum {q_path} 2>/dev/null | awk '{{print $1}}'); "
            f'[ "$current_hash" = {sh_quote(expected_sha256)} ] || exit 89; '
            f"chmod 600 {q_temporary} && mv -f {q_temporary} {q_path} "
            "&& echo __manifest_pid_refreshed"
        )
    except BaseException:
        with contextlib.suppress(Exception):
            session.exec(f"{_guard_lock_fence(lock)}rm -f {q_temporary}")
        raise
    if not result.success or "__manifest_pid_refreshed" not in result.stdout:
        with contextlib.suppress(Exception):
            session.exec(f"{_guard_lock_fence(lock)}rm -f {q_temporary}")
        raise GuardDeploymentConflictError(
            "remote Guard manifest changed during supervised PID refresh"
        )


def guard_status(
    target: str,
    port: int = 22,
    identity: Path | None = None,
    password: str | None = None,
    unit_name: str = "kcatta-guard",
    install_dir: str = "/var/lib/agent-guard",
) -> GuardStatus:
    """Probe whether the guard daemon is alive on ``target`` over SSH (B5).

    Checks the systemd unit's ``ActiveState`` first (the supervised path), then
    falls back to whether any ``agentd respond`` process is running. Lets the admin
    answer "is endpoint protection actually up on this host?" — previously
    unanswerable, since start-time only recorded the launch-moment PID.
    """
    unit = _validate_unit_name(unit_name)
    install_dir = _validate_guard_install_dir(install_dir)
    key = bootstrap.ensure_key_auth(target, port, identity, password)
    user, host = split_user_host(target)
    with SshSession(host=host, user=user, key_path=key, port=port) as session:
        return _guard_status_over(session, unit, install_dir)


def _guard_status_over(
    session: SshSession,
    unit: str,
    install_dir: str = "/var/lib/agent-guard",
    *,
    lock: _GuardDeploymentLock | None = None,
) -> GuardStatus:
    """The probe logic, factored out so it can run over any session (testable)."""
    q_unit = sh_quote(unit)
    q_ready = sh_quote(f"{install_dir}/{GUARD_READY_FILE_NAME}")
    ready_probe = (
        f"if [ -f {q_ready} ] && [ ! -L {q_ready} ]; then "
        f"ready=$(cat {q_ready} 2>/dev/null); else ready=; fi; "
        "echo __ready=$ready"
    )
    out = session.exec(
        f"{_guard_lock_fence(lock)}if command -v systemctl >/dev/null 2>&1; then "
        f"  echo __active=$(systemctl is-active {q_unit} 2>/dev/null); "
        f"  echo __pid=$(systemctl show -p MainPID --value {q_unit} 2>/dev/null); "
        f"  {ready_probe}; "
        f"else echo __no_systemd; fi"
    )
    if not out.success:
        raise RuntimeError("failed to inspect Guard systemd status")
    text = out.stdout
    if "__active=" in text:
        active = _marker_value(text, "__active=")
        pid = _marker_value(text, "__pid=")
        ready = _marker_value(text, "__ready=")
        valid_pid = pid if pid and pid.isdigit() and pid != "0" else None
        alive = active == "active" and valid_pid is not None and ready == valid_pid
        if active != "active":
            detail = f"unit {unit} is {active or 'unknown'}"
        elif valid_pid is None:
            detail = f"unit {unit} is active but has no MainPID"
        elif ready != valid_pid:
            detail = (
                f"unit {unit} is active but sensor readiness is missing or belongs to another PID"
            )
        else:
            detail = f"unit {unit} is active and all configured sensors are ready"
        return GuardStatus(
            alive=alive,
            supervisor="systemd",
            detail=detail,
            pid=valid_pid,
        )
    # No systemd — fall back to a process check, anchored to this deployment's
    # absolute binary path. A host may run another agentd instance; accepting a
    # generic ``agentd respond`` match would corrupt manifest/PID reconciliation
    # and could make teardown report the wrong daemon. Bracketing the first path
    # character keeps pgrep from matching its own wrapper shell.
    respond_pattern = sh_quote(_bracket_first(f"{install_dir}/agentd respond"))
    guard_pattern = sh_quote(_bracket_first(f"{install_dir}/agentd guard"))
    proc = session.exec(
        f"{_guard_lock_fence(lock)}"
        f"pid=$({{ pgrep -f {respond_pattern}; pgrep -f {guard_pattern}; }} | head -n1); "
        f"echo __pid=$pid; {ready_probe}"
    )
    if not proc.success:
        raise RuntimeError("failed to inspect Guard process status")
    pid = _marker_value(proc.stdout, "__pid=")
    ready = _marker_value(proc.stdout, "__ready=")
    valid_pid = pid if pid and pid.isdigit() and pid != "0" else None
    alive = valid_pid is not None and ready == valid_pid
    detail = (
        "agentd respond process found and all configured sensors are ready"
        if alive
        else (
            "agentd respond process found but sensor readiness is missing or belongs to another PID"
            if valid_pid
            else "agentd respond process not found"
        )
    )
    return GuardStatus(
        alive=alive,
        supervisor="process",
        detail=detail,
        pid=valid_pid,
    )


def _marker_value(stdout: str, marker: str) -> str:
    """Return the value following the last ``<marker>`` line in stdout, else ''."""
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if stripped.startswith(marker):
            return stripped[len(marker) :].strip()
    return ""


def stop_guard_daemon(
    opts: GuardDeployOptions,
    *,
    expected_manifest: GuardDeploymentManifest | None = None,
) -> GuardStatus:
    """Stop and uninstall the guard daemon on ``target`` — the inverse of start.

    Stops the systemd unit (transient ``--collect`` units vanish on stop;
    ``reset-failed`` clears a crashed one), kills any stray ``agentd respond``
    process left by the ``setsid`` fallback, then removes the install dir. The
    independently managed `/var/lib/kcatta/agentd/identity` generations remain
    for restart/rotation and central revocation workflows. Returns a GuardStatus
    reflecting the post-stop state.

    Lets the 常驻 (resident) management view answer the lifecycle gap: a guard
    daemon could be started and probed but never stopped from Form.
    """
    unit = _validate_unit_name(opts.unit_name)
    install = _validate_guard_install_dir(opts.install_dir)
    if expected_manifest is not None and not isinstance(expected_manifest, GuardDeploymentManifest):
        raise TypeError("expected_manifest must be a GuardDeploymentManifest")
    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)
    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        _prepare_guard_install_over(session, install)
        lock = _acquire_guard_deployment_lock(session, install)
        try:
            if expected_manifest is not None:
                current_manifest = _guard_deployment_manifest_over(
                    session,
                    install,
                    lock=lock,
                )
                if current_manifest != expected_manifest:
                    current_id = (
                        current_manifest.deployment_id if current_manifest is not None else "absent"
                    )
                    raise GuardDeploymentConflictError(
                        "remote Guard generation changed before conditional stop "
                        f"(expected {expected_manifest.deployment_id}, current {current_id})"
                    )
            return _guard_stop_over(session, unit, install, lock=lock)
        finally:
            _release_guard_deployment_lock(session, lock)


def _bracket_first(pattern: str) -> str:
    """Wrap the first char in a one-char class so a `pkill -f`/`pgrep -f` pattern
    cannot match the very command line that carries it (avoids self-kill)."""
    return f"[{pattern[0]}]{pattern[1:]}" if pattern else pattern


def _guard_stop_over(
    session: SshSession,
    unit: str,
    install_dir: str,
    *,
    lock: _GuardDeploymentLock | None = None,
) -> GuardStatus:
    """The stop logic, factored out so it can run over any session (testable).

    Tears the daemon down, then **re-probes** and returns the real liveness — a
    stop that was denied/EPERM/respawned reports ``alive=True`` honestly instead
    of an assumed-success ``alive=False``.
    """
    q_unit = sh_quote(unit)
    q_install = sh_quote(install_dir)
    # Path-anchored, bracketed pkill: match only THIS install's daemon
    # (`<install>/agentd respond|guard …`). Kill both primary and legacy alias
    # forms. The leading `[x]` also stops pkill matching itself.
    kill_respond = sh_quote(_bracket_first(f"{install_dir}/agentd respond"))
    kill_guard = sh_quote(_bracket_first(f"{install_dir}/agentd guard"))
    # Each step is independent (`;`) and the trailing echo always runs, so stdout
    # carries the marker as long as the SSH channel ran the command at all — the
    # honest liveness signal comes from the re-probe below, not this marker.
    out = session.exec(
        f"{_guard_lock_fence(lock)}if command -v systemctl >/dev/null 2>&1; then "
        f"  systemctl stop {q_unit} >/dev/null 2>&1; "
        f"  systemctl reset-failed {q_unit} >/dev/null 2>&1; "
        f"fi; "
        f"pkill -f {kill_respond} >/dev/null 2>&1; "
        f"pkill -f {kill_guard} >/dev/null 2>&1; "
        f"rm -rf {q_install} >/dev/null 2>&1; "
        f"echo __stopped"
    )
    if "__stopped" not in out.stdout:
        raise RuntimeError(
            f"failed to stop guard daemon (unit {unit})\n"
            f"stdout: {out.stdout.strip()}\nstderr: {out.stderr.strip()}"
        )
    status = _guard_status_over(session, unit, install_dir)
    detail = (
        f"guard daemon stopped; install dir {install_dir} removed"
        if not status.alive
        else f"stop issued but daemon still reported alive ({status.detail}) — "
        "it may be respawning or the stop was denied"
    )
    return GuardStatus(
        alive=status.alive, supervisor=status.supervisor, detail=detail, pid=status.pid
    )


def _parse_marked_pid(stdout: str) -> str:
    """Extract the PID from a `__pid=<n>` marker line, or '' if absent."""
    for line in stdout.splitlines():
        marker = line.strip()
        if marker.startswith(_GUARD_PID_MARKER):
            value = marker[len(_GUARD_PID_MARKER) :].strip()
            if value.isdigit():
                return value
    return ""
