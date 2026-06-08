"""SSH agent-mode remote scan.

Ship a static ``agent`` binary to the target over SSH, run ``agent host`` in
place against the live filesystem, pull the per-asset JSON back, then remove all
traces. Needs only SSH access and a writable directory on the target — no
snapshot, NBD, or kernel module. Faithful Python port of the former Rust
``agent-remote`` ``agent.rs``.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from pathlib import Path

from . import bootstrap
from ._util import (
    expected_files,
    parse_marked_exit,
    sh_quote,
    sha256_file,
    short_id,
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
    """Also run ClamAV on the target (`agent host --malware`; needs clamd there)."""

    jobs: int | None = None
    clamd_socket: str | None = None


@dataclass
class AgentScanOptions:
    """Parameters for :func:`run_agent_scan`."""

    target: str  # user@host
    agent_binary: Path
    output_dir: Path
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
            print(f"[fusion.deploy] cleanup rm -rf {self.path} failed: {exc}")
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

    if not opts.agent_binary.is_file():
        raise FileNotFoundError(
            f"agent binary not found: {opts.agent_binary}\n"
            "build a static agent first, e.g.:\n"
            "  rustup target add x86_64-unknown-linux-musl\n"
            "  cargo build -p agent-runtime --no-default-features --features host,malware "
            "--target x86_64-unknown-linux-musl --release"
        )

    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = opts.target.split("@", 1)

    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        _probe_arch_compatible(session)
        with _RemoteWorkdir(session, task_id) as workdir:
            remote_bin = f"{workdir.path}/agent"
            remote_out = f"{workdir.path}/out"

            session.upload(opts.agent_binary, remote_bin)
            _verify_upload(session, opts.agent_binary, remote_bin)

            q_bin = sh_quote(remote_bin)
            q_out = sh_quote(remote_out)
            command = (
                f"chmod +x {q_bin} && mkdir -p {q_out} && "
                f"{q_bin} host -r {sh_quote(opts.scan_root)} -t {sh_quote(opts.scan_target)} "
                f"--windows-packages {sh_quote(opts.windows_packages)} -o {q_out}"
            )
            if opts.malware is not None:
                command += " --malware"
                if opts.malware.jobs:
                    command += f" --malware-jobs {int(opts.malware.jobs)}"
                if opts.malware.clamd_socket:
                    command += f" --clamd-socket {sh_quote(opts.malware.clamd_socket)}"
            command += "; echo __exit=$?"

            run = session.exec(command)
            if parse_marked_exit(run.stdout) != 0:
                raise RuntimeError(
                    f"remote agent host failed (exit {parse_marked_exit(run.stdout)})\n"
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


def _probe_arch_compatible(session: SshSession) -> None:
    arch = session.exec("uname -m").stdout.strip()
    if arch not in ("x86_64", "amd64"):
        raise RuntimeError(
            f"target arch {arch!r} not supported by the shipped binary "
            "(build a matching `agent` target)"
        )


def _verify_upload(session: SshSession, local: Path, remote_path: str) -> None:
    local_sum = sha256_file(local)
    out = session.exec(f"sha256sum {sh_quote(remote_path)} 2>/dev/null")
    remote_sum = out.stdout.split()[0] if out.stdout.split() else ""
    if not remote_sum:
        print("[fusion.deploy] sha256sum unavailable on target; skipping integrity check")
        return
    if remote_sum != local_sum:
        raise RuntimeError(
            f"uploaded binary sha256 mismatch (local {local_sum}, remote {remote_sum})"
        )


def _remote_exists(session: SshSession, path: str) -> bool:
    return "__y" in session.exec(f"test -f {sh_quote(path)} && echo __y").stdout
