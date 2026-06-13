"""SSH agent-mode remote scan.

Ship a static ``agent`` binary to the target over SSH, run ``agent host`` in
place against the live filesystem, pull the per-asset JSON back, then remove all
traces. Needs only SSH access and a writable directory on the target — no
snapshot, NBD, or kernel module. Faithful Python port of the former Rust
``agent-remote`` ``agent.rs``.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import bootstrap
from ._util import (
    expected_files,
    parse_marked_exit,
    sh_quote,
    sha256_file,
    short_id,
    split_user_host,
    validate_scan_options,
)
from .ssh import SshSession

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
    """Also run the built-in malware signature scan on the target (`agent-host --malware`)."""

    jobs: int | None = None


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
            print(f"[analyzer.deploy] cleanup rm -rf {self.path} failed: {exc}")
        # Remove the scdr parent we created, only when empty and clearly ours.
        if self._created_parent and self.parent.startswith("/") and self.parent.endswith("/scdr"):
            with contextlib.suppress(Exception):
                self._session.exec(f"rmdir {sh_quote(self.parent)} 2>/dev/null")


def run_agent_scan(opts: AgentScanOptions) -> AgentScanReport:
    """Run the full agent pipeline: bootstrap auth, upload, exec, pull, cleanup."""
    task_id = opts.task_id or short_id()

    # Reject unknown scan_target / windows_packages BEFORE building the remote
    # command (these flow into the target shell). Quoting below is defense in
    # depth; this whitelist is the primary guard.
    validate_scan_options(opts.scan_target, opts.windows_packages)

    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)

    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        arch = _probe_arch(session)
        binary = resolve_agent_binary(arch, "agent-host", opts.agent_binary)
        _require_binary(binary, arch)
        with _RemoteWorkdir(session, task_id) as workdir:
            remote_bin = f"{workdir.path}/agent-host"
            remote_out = f"{workdir.path}/out"

            session.upload(binary, remote_bin)
            _verify_upload(session, binary, remote_bin)

            q_bin = sh_quote(remote_bin)
            q_out = sh_quote(remote_out)
            # agent-host is a single-command binary (no `host` subcommand).
            command = (
                f"chmod +x {q_bin} && mkdir -p {q_out} && "
                f"{q_bin} -r {sh_quote(opts.scan_root)} -t {sh_quote(opts.scan_target)} "
                f"--windows-packages {sh_quote(opts.windows_packages)} -o {q_out}"
            )
            if opts.malware is not None:
                command += " --malware"
                if opts.malware.jobs:
                    command += f" --malware-jobs {int(opts.malware.jobs)}"
            command += "; echo __exit=$?"

            run = session.exec(command)
            if parse_marked_exit(run.stdout) != 0:
                raise RuntimeError(
                    f"remote agent-host failed (exit {parse_marked_exit(run.stdout)})\n"
                    f"stdout: {run.stdout.strip()}\nstderr: {run.stderr.strip()}"
                )

            opts.output_dir.mkdir(parents=True, exist_ok=True)
            wanted = list(expected_files(opts.scan_target))
            if opts.malware is not None:
                wanted.append("malware.json")

            files: list[Path] = []
            for fname in wanted:
                remote_file = f"{remote_out}/{fname}"
                if not _remote_exists(session, remote_file):
                    continue
                local_file = opts.output_dir / fname
                session.download(remote_file, local_file)
                files.append(local_file)

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
        raise RuntimeError(
            f"target arch {raw!r} not supported (shipped: {sorted(_ARCH_TRIPLE)})"
        )
    return arch


def _agent_target_dir() -> Path:
    """Cargo target root on the analyzer host holding the per-arch musl release dirs."""
    return Path(os.getenv("ANALYZER_AGENT_TARGET_DIR", "../agent/target"))


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


def _verify_upload(session: SshSession, local: Path, remote_path: str) -> None:
    local_sum = sha256_file(local)
    out = session.exec(f"sha256sum {sh_quote(remote_path)} 2>/dev/null")
    remote_sum = out.stdout.split()[0] if out.stdout.split() else ""
    if not remote_sum:
        print("[analyzer.deploy] sha256sum unavailable on target; skipping integrity check")
        return
    if remote_sum != local_sum:
        raise RuntimeError(
            f"uploaded binary sha256 mismatch (local {local_sum}, remote {remote_sum})"
        )


def _remote_exists(session: SshSession, path: str) -> bool:
    return "__y" in session.exec(f"test -f {sh_quote(path)} && echo __y").stdout


# --------------------------------------------------------------------------
# Flow capture (one-shot) and guard (persistent daemon) remote scheduling.
# These mirror the host pipeline above: SSH in, deploy the lean capability
# binary, run it. `flow` is one-shot (pull the FlowBatch back, like host);
# `guard` is a long-running daemon (start it detached, leave it running).
# --------------------------------------------------------------------------


@dataclass
class FlowCaptureOptions:
    """Parameters for :func:`run_flow_capture` (deploy + one-shot agent-flow)."""

    target: str  # user@host
    output_dir: Path
    # Explicit agent-flow override; when None, resolved from the target's arch.
    agent_binary: Path | None = None
    port: int = 22
    identity: Path | None = None
    password: str | None = None
    task_id: str | None = None
    pcap: bool = False
    iface: str = "any"
    duration: int = 5
    bpf: str = "tcp or udp or icmp"


def run_flow_capture(opts: FlowCaptureOptions) -> Path:
    """Deploy agent-flow, run one capture cycle, pull the `FlowBatch` JSON back.

    Returns the local path to the pulled `flow.json`. One-shot (mock by default,
    or live pcap when ``opts.pcap``); the remote work dir is cleaned up on exit.
    """
    task_id = opts.task_id or short_id()
    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)

    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        arch = _probe_arch(session)
        binary = resolve_agent_binary(arch, "agent-flow", opts.agent_binary)
        _require_binary(binary, arch)
        with _RemoteWorkdir(session, task_id) as workdir:
            remote_bin = f"{workdir.path}/agent-flow"
            remote_out = f"{workdir.path}/flow.json"

            session.upload(binary, remote_bin)
            _verify_upload(session, binary, remote_bin)

            q_bin = sh_quote(remote_bin)
            command = f"chmod +x {q_bin} && {q_bin} capture --out {sh_quote(remote_out)}"
            if opts.pcap:
                command += (
                    f" --pcap --iface {sh_quote(opts.iface)} "
                    f"--duration {int(opts.duration)} --bpf {sh_quote(opts.bpf)}"
                )
            command += "; echo __exit=$?"

            run = session.exec(command)
            if parse_marked_exit(run.stdout) != 0:
                raise RuntimeError(
                    f"remote agent-flow capture failed (exit {parse_marked_exit(run.stdout)})\n"
                    f"stdout: {run.stdout.strip()}\nstderr: {run.stderr.strip()}"
                )
            if not _remote_exists(session, remote_out):
                raise RuntimeError(f"remote capture produced no FlowBatch at {remote_out}")

            opts.output_dir.mkdir(parents=True, exist_ok=True)
            local = opts.output_dir / "flow.json"
            session.download(remote_out, local)

    return local


@dataclass
class GuardDeployOptions:
    """Parameters for :func:`start_guard_daemon` (deploy + start `agent guard`)."""

    target: str  # user@host
    upload: str  # analyzer base URL the daemon pushes GuardEventBatch to
    # The `agent` umbrella binary (uploading lives there); None → resolved by arch.
    agent_binary: Path | None = None
    install_dir: str = "/var/lib/agent-guard"
    config: Path | None = None  # local guard.json to upload (optional)
    port: int = 22
    identity: Path | None = None
    password: str | None = None


def start_guard_daemon(opts: GuardDeployOptions) -> str:
    """Deploy the `agent` umbrella binary and start `agent guard` as a detached daemon.

    The daemon keeps running after the SSH session closes and pushes
    `GuardEventBatch`es to ``opts.upload``. Returns the remote PID. Unlike the
    one-shot host/flow paths, this intentionally does **not** clean up — the
    install dir and the running process persist.

    Uses the `agent` binary (not the lean `agent-guard`): uploading lives in the
    umbrella, so `agent guard --upload <analyzer>` is what pushes events to analyzer.
    """
    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)
    install = opts.install_dir

    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        arch = _probe_arch(session)
        binary = resolve_agent_binary(arch, "agent", opts.agent_binary)
        _require_binary(binary, arch)
        q_install = sh_quote(install)
        out = session.exec(f"mkdir -p {q_install} && chmod 700 {q_install} && echo __ok")
        if "__ok" not in out.stdout:
            raise RuntimeError(
                f"failed to create guard install dir {install}: {out.stderr.strip()}"
            )

        remote_bin = f"{install}/agent"
        session.upload(binary, remote_bin)
        _verify_upload(session, binary, remote_bin)

        config_arg = ""
        if opts.config is not None:
            remote_cfg = f"{install}/guard.json"
            session.upload(opts.config, remote_cfg)
            config_arg = f" --config {sh_quote(remote_cfg)}"

        q_bin = sh_quote(remote_bin)
        q_log = sh_quote(f"{install}/guard.log")
        # `setsid` + full redirection + `< /dev/null` detaches the daemon so it
        # survives the SSH channel closing (no SIGHUP, no stdio dependency).
        # `agent guard --upload <analyzer>` — only the umbrella uploads.
        start = (
            f"chmod +x {q_bin} && "
            f"setsid {q_bin} guard{config_arg} --upload {sh_quote(opts.upload)} "
            f"> {q_log} 2>&1 < /dev/null & echo __pid=$!"
        )
        run = session.exec(start)
        pid = _parse_marked_pid(run.stdout)
        if not pid:
            raise RuntimeError(
                f"failed to start guard daemon on {opts.target}\n"
                f"stdout: {run.stdout.strip()}\nstderr: {run.stderr.strip()}"
            )

    return pid


def _parse_marked_pid(stdout: str) -> str:
    """Extract the PID from a `__pid=<n>` marker line, or '' if absent."""
    for line in stdout.splitlines():
        marker = line.strip()
        if marker.startswith("__pid="):
            value = marker[len("__pid=") :].strip()
            if value.isdigit():
                return value
    return ""
