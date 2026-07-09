"""SSH agent-mode remote scan.

Ship the static capability binary selected for the requested scan over SSH,
run it in place against the live target, pull the JSON artifact back, then
clean up one-shot work dirs. Guard deployment is the persistent exception: it
ships `agentd` and starts `agentd respond --upload` as a resident daemon.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import tempfile
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

logger = logging.getLogger(__name__)

# A token safe to place verbatim in an env file that is both sourced by a shell
# (setsid fallback) and read by systemd `EnvironmentFile=`. The analyzer's own
# tokens are `secrets.token_urlsafe` / hex / base64, all within this set; a token
# with whitespace, quotes, `$`, backticks, or control chars is rejected so it can
# break neither parser.
_ENV_TOKEN_SAFE = re.compile(r"\A[A-Za-z0-9._~=+/-]+\Z")


def _token_is_env_safe(token: str) -> bool:
    """Whether ``token`` can be written verbatim into the guard daemon env file."""
    return bool(_ENV_TOKEN_SAFE.match(token))

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
    """Also run built-in malware scan on the target (`agent-collect-host --malware`)."""

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
            logger.warning("cleanup rm -rf %s failed: %s", self.path, exc)
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
        binary = resolve_agent_binary(arch, "agent-collect-host", opts.agent_binary)
        _require_binary(binary, arch)
        with _RemoteWorkdir(session, task_id) as workdir:
            remote_bin = f"{workdir.path}/agent-collect-host"
            remote_out = f"{workdir.path}/out"

            session.upload(binary, remote_bin)
            _verify_upload(session, binary, remote_bin)

            q_bin = sh_quote(remote_bin)
            q_out = sh_quote(remote_out)
            # agent-collect-host is a single-command binary (no `host` subcommand).
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
                    f"remote agent-collect-host failed (exit {parse_marked_exit(run.stdout)})\n"
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


def resolve_windows_agent_binary(
    name: str = "agent-collect-host.exe", explicit: Path | None = None
) -> Path:
    """Resolve the Windows agent binary (WinRM scans need the .exe, not the musl build)."""
    if explicit is not None:
        return explicit
    return _agent_target_dir() / "x86_64-pc-windows-msvc" / "release" / name


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
        logger.warning(
            "sha256sum unavailable on %s; skipping upload integrity check", session.host
        )
        return
    if remote_sum != local_sum:
        raise RuntimeError(
            f"uploaded binary sha256 mismatch (local {local_sum}, remote {remote_sum})"
        )


def _remote_exists(session: SshSession, path: str) -> bool:
    return "__y" in session.exec(f"test -f {sh_quote(path)} && echo __y").stdout


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


def run_trace_capture(opts: TraceCaptureOptions) -> Path:
    """Deploy agent-collect-trace, run one capture cycle, pull the `TraceBatch` JSON back.

    Returns the local path to the pulled `flow.json`. One-shot (mock by default,
    or live pcap when ``opts.pcap``); the remote work dir is cleaned up on exit.
    """
    task_id = opts.task_id or short_id()
    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)

    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        arch = _probe_arch(session)
        binary = resolve_agent_binary(arch, "agent-collect-trace", opts.agent_binary)
        _require_binary(binary, arch)
        with _RemoteWorkdir(session, task_id) as workdir:
            remote_bin = f"{workdir.path}/agent-collect-trace"
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
    upload: str  # analyzer base URL the daemon pushes GuardEventBatch to
    # The `agentd` umbrella binary (uploading lives there); None → resolved by arch.
    agent_binary: Path | None = None
    install_dir: str = "/var/lib/agent-guard"
    config: Path | None = None  # local guard.json to upload (optional)
    port: int = 22
    identity: Path | None = None
    password: str | None = None
    # Bearer token the remote daemon must send so analyzer (when auth is enabled)
    # accepts its GuardEventBatch uploads. None → fall back to the analyzer's own
    # ANALYZER_API_TOKEN env. Injected via a 0600 env file, never on the cmdline.
    api_token: str | None = None
    # systemd unit name for the supervised daemon (deterministic per host so the
    # status probe can find it). Validated to a safe charset before use.
    unit_name: str = "kcatta-guard"


# systemd unit / setsid markers parsed back from remote stdout.
_GUARD_UNIT_MARKER = "__unit="
_GUARD_PID_MARKER = "__pid="

# A systemd unit name must be a plain token (letters/digits/-_.@); reject
# anything else so it can never break out of the systemd-run invocation.
_UNIT_NAME_OK = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@"
)


def _validate_unit_name(name: str) -> str:
    if not name or any(c not in _UNIT_NAME_OK for c in name):
        raise ValueError(f"invalid systemd unit name {name!r}")
    return name


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
    umbrella, so `agentd respond --upload <analyzer>` is what pushes events to analyzer.
    """
    unit = _validate_unit_name(opts.unit_name)
    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)
    install = opts.install_dir

    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        arch = _probe_arch(session)
        binary = resolve_agent_binary(arch, "agentd", opts.agent_binary)
        _require_binary(binary, arch)
        q_install = sh_quote(install)
        out = session.exec(f"mkdir -p {q_install} && chmod 700 {q_install} && echo __ok")
        if "__ok" not in out.stdout:
            raise RuntimeError(
                f"failed to create guard install dir {install}: {out.stderr.strip()}"
            )

        remote_bin = f"{install}/agentd"
        session.upload(binary, remote_bin)
        _verify_upload(session, binary, remote_bin)

        config_arg = ""
        if opts.config is not None:
            remote_cfg = f"{install}/guard.json"
            session.upload(opts.config, remote_cfg)
            config_arg = f" --config {sh_quote(remote_cfg)}"

        env_file = _install_guard_env(session, install, opts.api_token)

        run = session.exec(
            _guard_start_command(remote_bin, install, unit, config_arg, opts.upload, env_file)
        )
        pid = _parse_marked_pid(run.stdout)
        unit_started = _GUARD_UNIT_MARKER in run.stdout
        if not pid and not unit_started:
            raise RuntimeError(
                f"failed to start guard daemon on {opts.target}\n"
                f"stdout: {run.stdout.strip()}\nstderr: {run.stderr.strip()}"
            )
        if unit_started and not pid:
            # systemd path: resolve the unit's MainPID for the caller.
            pid = _systemd_unit_pid(session, unit)

    return pid or ""


def _install_guard_env(session: SshSession, install: str, api_token: str | None) -> str | None:
    """Write a 0600 ``agentd.env`` holding ``ANALYZER_API_TOKEN`` and return its path.

    Without this the remote ``agentd respond`` sends no bearer token, so on an
    auth-enabled analyzer every GuardEventBatch is rejected with 401 — a
    permanent failure that is *not* retried, silently losing all guard telemetry.

    The token is resolved from ``api_token`` (the ingest-scoped token the API
    passes in) or, for direct-CLI deploys, from ``ANALYZER_INGEST_TOKEN`` and then
    ``ANALYZER_API_TOKEN``. Distributing the ingest-scoped token keeps the
    analyzer's master credential off the monitored endpoint. It is uploaded as a
    file (over SFTP, never on a command line) so it cannot leak via ``ps`` / the
    systemd journal. Returns the remote env-file path, or ``None`` when there is no
    usable token (auth-off deployments keep working unchanged).
    """
    token = (
        api_token
        if api_token is not None
        else os.getenv("ANALYZER_INGEST_TOKEN") or os.getenv("ANALYZER_API_TOKEN") or ""
    ).strip()
    if not token:
        return None
    if not _token_is_env_safe(token):
        logger.warning(
            "ANALYZER_API_TOKEN has characters unsafe for an env file; guard daemon "
            "will upload WITHOUT auth and its events may be rejected"
        )
        return None

    remote_env = f"{install}/agentd.env"
    # tempfile.mkstemp creates the local file 0600, so the token is never
    # world-readable even briefly on the analyzer host.
    fd, local_name = tempfile.mkstemp(prefix="agentd-env-")
    local_env = Path(local_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(f"ANALYZER_API_TOKEN={token}\n")
        session.upload(local_env, remote_env)
    finally:
        local_env.unlink(missing_ok=True)
    session.exec(f"chmod 600 {sh_quote(remote_env)}")
    return remote_env


def _guard_start_command(
    remote_bin: str,
    install: str,
    unit: str,
    config_arg: str,
    upload: str,
    env_file: str | None = None,
) -> str:
    """Build the remote start command: systemd-run when available, else setsid.

    A single shell command so it works over one SSH channel: if ``systemd-run``
    exists, start a transient unit with ``Restart=on-failure`` (auto-restart on
    crash/OOM); otherwise fall back to the detached ``setsid`` form. Every
    operator-controlled value is ``sh_quote``-escaped; the unit name is validated
    to a safe charset by the caller.

    When ``env_file`` is given (the 0600 token file), the bearer token is fed to
    the daemon's environment — via ``EnvironmentFile=`` for systemd (a transient
    unit starts with a clean env, so an exported shell var would not reach it) and
    by sourcing the file for the setsid fallback. Either way the token enters the
    process environment, never its argv.
    """
    q_bin = sh_quote(remote_bin)
    q_log = sh_quote(f"{install}/guard.log")
    q_upload = sh_quote(upload)
    q_unit = sh_quote(unit)
    q_env = sh_quote(env_file) if env_file else None
    # `respond --upload <analyzer>` — only the umbrella uploads. config_arg is
    # already quoted (or empty). (`guard` remains a clap alias of `respond`.)
    guard_args = f"respond{config_arg} --upload {q_upload}"
    systemd_env = f"--property=EnvironmentFile={q_env} " if q_env else ""
    systemd = (
        f"systemd-run --unit={q_unit} --collect "
        f"--property=Restart=on-failure --property=RestartSec=5 "
        f"{systemd_env}"
        f"-- {q_bin} {guard_args} && echo {_GUARD_UNIT_MARKER}{q_unit}"
    )
    # setsid inherits the shell env, so source the 0600 file first (keeps the
    # token out of argv); `set -a` exports the assignments to the child.
    setsid_env = f"set -a; . {q_env}; set +a; " if q_env else ""
    setsid = (
        f"{setsid_env}setsid {q_bin} {guard_args} "
        f"> {q_log} 2>&1 < /dev/null & echo {_GUARD_PID_MARKER}$!"
    )
    return (
        f"chmod +x {q_bin} && "
        f"if command -v systemd-run >/dev/null 2>&1; then {systemd}; "
        f"else {setsid}; fi"
    )


def _systemd_unit_pid(session: SshSession, unit: str) -> str:
    """Best-effort MainPID of a systemd unit (empty string when unknown)."""
    out = session.exec(
        f"systemctl show -p MainPID --value {sh_quote(unit)} 2>/dev/null"
    )
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


def guard_status(
    target: str,
    port: int = 22,
    identity: Path | None = None,
    password: str | None = None,
    unit_name: str = "kcatta-guard",
) -> GuardStatus:
    """Probe whether the guard daemon is alive on ``target`` over SSH (B5).

    Checks the systemd unit's ``ActiveState`` first (the supervised path), then
    falls back to whether any ``agentd respond`` process is running. Lets the admin
    answer "is endpoint protection actually up on this host?" — previously
    unanswerable, since start-time only recorded the launch-moment PID.
    """
    unit = _validate_unit_name(unit_name)
    key = bootstrap.ensure_key_auth(target, port, identity, password)
    user, host = split_user_host(target)
    with SshSession(host=host, user=user, key_path=key, port=port) as session:
        return _guard_status_over(session, unit)


def _guard_status_over(session: SshSession, unit: str) -> GuardStatus:
    """The probe logic, factored out so it can run over any session (testable)."""
    q_unit = sh_quote(unit)
    out = session.exec(
        f"if command -v systemctl >/dev/null 2>&1; then "
        f"  echo __active=$(systemctl is-active {q_unit} 2>/dev/null); "
        f"  echo __pid=$(systemctl show -p MainPID --value {q_unit} 2>/dev/null); "
        f"else echo __no_systemd; fi"
    )
    text = out.stdout
    if "__active=" in text:
        active = _marker_value(text, "__active=")
        pid = _marker_value(text, "__pid=")
        alive = active == "active"
        return GuardStatus(
            alive=alive,
            supervisor="systemd",
            detail=f"unit {unit} is {active or 'unknown'}",
            pid=pid if pid and pid.isdigit() and pid != "0" else None,
        )
    # No systemd — fall back to a process check. Prefer `agentd respond`; also
    # accept legacy `agentd guard` (clap alias / older deploys). Bracketed
    # `[a]gentd` keeps pgrep from matching its own wrapper shell.
    proc = session.exec(
        "pgrep -f '[a]gentd respond' | head -n1; "
        "pgrep -f '[a]gentd guard' | head -n1"
    )
    pid = ""
    for line in proc.stdout.strip().splitlines():
        candidate = line.strip()
        if candidate.isdigit():
            pid = candidate
            break
    alive = bool(pid)
    return GuardStatus(
        alive=alive,
        supervisor="process",
        detail="agentd respond process " + ("found" if alive else "not found"),
        pid=pid if alive else None,
    )


def _marker_value(stdout: str, marker: str) -> str:
    """Return the value following the last ``<marker>`` line in stdout, else ''."""
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if stripped.startswith(marker):
            return stripped[len(marker) :].strip()
    return ""


def stop_guard_daemon(opts: GuardDeployOptions) -> GuardStatus:
    """Stop and uninstall the guard daemon on ``target`` — the inverse of start.

    Stops the systemd unit (transient ``--collect`` units vanish on stop;
    ``reset-failed`` clears a crashed one), kills any stray ``agentd respond``
    process left by the ``setsid`` fallback, then removes the install dir so the
    host is left clean. Returns a GuardStatus reflecting the post-stop state.

    Lets the 常驻 (resident) management view answer the lifecycle gap: a guard
    daemon could be started and probed but never stopped from analyzer.
    """
    unit = _validate_unit_name(opts.unit_name)
    key = bootstrap.ensure_key_auth(opts.target, opts.port, opts.identity, opts.password)
    user, host = split_user_host(opts.target)
    with SshSession(host=host, user=user, key_path=key, port=opts.port) as session:
        return _guard_stop_over(session, unit, opts.install_dir)


def _bracket_first(pattern: str) -> str:
    """Wrap the first char in a one-char class so a `pkill -f`/`pgrep -f` pattern
    cannot match the very command line that carries it (avoids self-kill)."""
    return f"[{pattern[0]}]{pattern[1:]}" if pattern else pattern


def _guard_stop_over(session: SshSession, unit: str, install_dir: str) -> GuardStatus:
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
        f"if command -v systemctl >/dev/null 2>&1; then "
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
    status = _guard_status_over(session, unit)
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
