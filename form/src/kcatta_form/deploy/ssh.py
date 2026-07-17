"""OpenSSH-over-paramiko transport for Form-owned remote scans.

One :class:`SshSession` keeps a single TCP connection (paramiko ``Transport``)
and opens a fresh channel per command / SFTP transfer — the same "one
connection, many channels" multiplexing the former Rust pipeline got from
OpenSSH ``ControlMaster``. Key auth only; the one-shot password bootstrap that
installs the managed key lives in :mod:`kcatta_form.deploy.bootstrap`.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import paramiko

from ._util import (
    current_deploy_cancellation_probe,
    max_scan_artifact_bytes,
    max_scan_total_bytes,
    remote_command_timeout_seconds,
)

DEFAULT_CONNECT_TIMEOUT = 15.0
DEFAULT_HOST_KEY_POLICY = "accept-new"
HOST_KEY_POLICY_ENV = "FORM_SSH_HOST_KEY_POLICY"
KNOWN_HOSTS_ENV = "FORM_SSH_KNOWN_HOSTS"

_KNOWN_HOSTS_LOCK = threading.Lock()

try:  # pragma: no cover - Form runs on Linux; fallback keeps imports portable.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


def ssh_host_key_policy() -> str:
    """Return the configured SSH host-key policy (``accept-new`` or ``strict``).

    ``accept-new`` is trust-on-first-use: the first key is persisted and every
    later connection must present that same key. ``strict`` requires the host to
    have been provisioned in known_hosts before Form makes any connection.
    """
    policy = os.getenv(HOST_KEY_POLICY_ENV, DEFAULT_HOST_KEY_POLICY).strip().lower()
    if policy not in {"accept-new", "strict"}:
        raise ValueError(f"{HOST_KEY_POLICY_ENV} must be 'accept-new' or 'strict', got {policy!r}")
    return policy


def known_hosts_path() -> Path:
    """Persistent known_hosts path shared by scans and credential bootstrap."""
    configured = os.getenv(KNOWN_HOSTS_ENV)
    if configured and configured.strip():
        return Path(configured.strip()).expanduser()
    config_home = os.getenv("XDG_CONFIG_HOME")
    base = Path(config_home) if config_home else Path.home() / ".config"
    return base / "scdr" / "agent-remote" / "known_hosts"


def _ensure_known_hosts(path: Path) -> None:
    """Create/tighten a regular 0600 known_hosts file in a 0700 directory."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with contextlib.suppress(OSError):
        path.parent.chmod(0o700)
    if path.is_symlink():
        raise ValueError(f"{KNOWN_HOSTS_ENV} must not point to a symlink: {path}")
    if path.exists():
        if not path.is_file():
            raise ValueError(f"{KNOWN_HOSTS_ENV} must point to a regular file: {path}")
        with contextlib.suppress(OSError):
            path.chmod(0o600)
        return
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:  # another worker won the creation race
        if path.is_symlink() or not path.is_file():
            raise ValueError(
                f"unsafe {KNOWN_HOSTS_ENV} path appeared concurrently: {path}"
            ) from exc
        with contextlib.suppress(OSError):
            path.chmod(0o600)
        return
    os.close(descriptor)


@contextmanager
def _known_hosts_write_lock(path: Path) -> Iterator[None]:
    """Serialize first-use writes across threads and, on POSIX, processes."""
    lock_path = path.with_name(f"{path.name}.lock")
    with _KNOWN_HOSTS_LOCK:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        with contextlib.suppress(OSError):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "r+") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _save_host_keys(keys: paramiko.HostKeys, path: Path) -> None:
    """Atomically replace known_hosts so a crash cannot leave a partial file."""
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    os.close(descriptor)
    try:
        keys.save(str(temporary))
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


class AcceptNewHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Persist a first-seen key, but reject any key change for a known host."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def missing_host_key(
        self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey
    ) -> None:
        # SSHClient normally calls this only for an entirely new hostname. Reload
        # under a lock as well: another concurrent worker may have pinned a key
        # after this client loaded the file but before its handshake completed.
        with _known_hosts_write_lock(self._path):
            persisted = paramiko.HostKeys()
            persisted.load(str(self._path))
            known = persisted.lookup(hostname)
            if known is not None:
                expected = known.get(key.get_name())
                if expected != key:
                    fallback = expected or next(iter(known.values()))
                    raise paramiko.BadHostKeyException(hostname, key, fallback)
            else:
                persisted.add(hostname, key.get_name(), key)
                _save_host_keys(persisted, self._path)
            client.get_host_keys().add(hostname, key.get_name(), key)


def create_ssh_client() -> paramiko.SSHClient:
    """Create an SSH client with Form's single persistent host-key policy."""
    policy = ssh_host_key_policy()
    path = known_hosts_path()
    _ensure_known_hosts(path)

    client = paramiko.SSHClient()
    client.load_host_keys(str(path))
    if policy == "strict":
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(AcceptNewHostKeyPolicy(path))
    return client


@dataclass
class CommandOutput:
    """Result of one remote command. Non-zero exits are returned, not raised,
    so callers can probe for missing commands."""

    stdout: str
    stderr: str
    status: int

    @property
    def success(self) -> bool:
        return self.status == 0


class SshSession:
    """A key-authenticated, multiplexed SSH session to ``user@host``."""

    def __init__(
        self,
        host: str,
        user: str,
        key_path: Path,
        port: int = 22,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        command_timeout: float | None = None,
    ) -> None:
        self.host = host
        self.user = user
        self.command_timeout = command_timeout or remote_command_timeout_seconds()
        self._client = create_ssh_client()
        self._sftp: paramiko.SFTPClient | None = None
        self._downloaded_artifact_bytes = 0
        with self._bounded_operation("SSH connection", timeout=connect_timeout):
            self._client.connect(
                hostname=host,
                port=port,
                username=user,
                key_filename=str(key_path),
                look_for_keys=False,
                allow_agent=False,
                timeout=connect_timeout,
                banner_timeout=connect_timeout,
                auth_timeout=connect_timeout,
                channel_timeout=self.command_timeout,
            )

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}"

    @contextmanager
    def _bounded_operation(
        self,
        label: str,
        *,
        abort: Callable[[], None] | None = None,
        timeout: float | None = None,
    ) -> Iterator[None]:
        """Enforce a wall-clock bound, including slow trickle traffic.

        Paramiko channel timeouts are inactivity bounds. A hostile endpoint can
        evade them by sending one byte periodically, so a daemon timer closes
        the active operation once the configured budget expires. The same abort
        path observes the worker's cancellation context, so operator cancel,
        job timeout, shutdown, and lease loss unblock a channel immediately.
        """
        expired = threading.Event()
        interrupted = threading.Event()
        finished = threading.Event()
        abort_operation = abort or self._client.close
        operation_timeout = timeout or self.command_timeout

        def stop_operation(marker: threading.Event) -> None:
            if finished.is_set():
                return
            marker.set()
            with contextlib.suppress(Exception):
                abort_operation()

        timer = threading.Timer(operation_timeout, stop_operation, args=(expired,))
        timer.daemon = True
        timer.start()
        cancellation_probe = current_deploy_cancellation_probe()
        watcher: threading.Thread | None = None
        if cancellation_probe is not None:

            def watch_cancellation() -> None:
                while not finished.wait(0.05):
                    if cancellation_probe():
                        stop_operation(interrupted)
                        return

            if cancellation_probe():
                stop_operation(interrupted)
            else:
                watcher = threading.Thread(
                    target=watch_cancellation,
                    name="kcatta-ssh-cancel",
                    daemon=True,
                )
                watcher.start()
        try:
            yield
        except Exception as exc:
            if interrupted.is_set():
                raise InterruptedError(f"{label} cancelled for {self.target}") from exc
            if expired.is_set():
                raise TimeoutError(
                    f"{label} exceeded {operation_timeout:.1f}s for {self.target}"
                ) from exc
            raise
        finally:
            finished.set()
            timer.cancel()
            if watcher is not None:
                watcher.join(timeout=0.1)
        if interrupted.is_set():
            raise InterruptedError(f"{label} cancelled for {self.target}")
        if expired.is_set():
            raise TimeoutError(f"{label} exceeded {operation_timeout:.1f}s for {self.target}")

    def exec(self, command: str) -> CommandOutput:
        """Run ``command`` over a new channel; capture stdout/stderr/exit."""
        channel_holder: dict[str, paramiko.Channel] = {}

        def abort_channel() -> None:
            channel = channel_holder.get("channel")
            if channel is None:
                self._client.close()
            else:
                channel.close()

        with self._bounded_operation("SSH command", abort=abort_channel):
            _stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=self.command_timeout,
            )
            channel_holder["channel"] = stdout.channel
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            status = stdout.channel.recv_exit_status()
        return CommandOutput(stdout=out, stderr=err, status=status)

    def _sftp_client(self) -> paramiko.SFTPClient:
        if self._sftp is None:
            with self._bounded_operation("SFTP channel setup"):
                self._sftp = self._client.open_sftp()
            # SFTP operations use their channel's socket timeout; without this
            # a stalled put/stat/read can outlive both the job deadline and SSH
            # command timeout while the worker honestly retains its slot.
            self._sftp.get_channel().settimeout(self.command_timeout)
        return self._sftp

    def upload(self, local: Path, remote_path: str) -> None:
        """Upload a local file to ``remote_path`` on the target."""
        with self._bounded_operation("SFTP upload"):
            self._sftp_client().put(str(local), remote_path)

    def upload_bytes(self, payload: bytes, remote_path: str) -> None:
        """Stream secret bytes straight to SFTP without a local temporary file."""

        if not isinstance(payload, bytes):
            raise TypeError("SFTP payload must be bytes")
        with (
            self._bounded_operation("SFTP private upload"),
            self._sftp_client().open(remote_path, "wb") as output,
        ):
            view = memoryview(payload)
            for offset in range(0, len(view), 64 * 1024):
                output.write(view[offset : offset + 64 * 1024])
            output.flush()

    def download(self, remote_path: str, local: Path) -> None:
        """Stream one untrusted artifact with per-file and per-scan byte caps."""
        local.parent.mkdir(parents=True, exist_ok=True)
        sftp = self._sftp_client()
        per_file_limit = max_scan_artifact_bytes()
        total_limit = max_scan_total_bytes()
        with self._bounded_operation("SFTP stat"):
            remote_size = int(sftp.stat(remote_path).st_size)
        if remote_size > per_file_limit:
            raise RuntimeError(
                f"remote scan artifact {remote_path} is {remote_size} bytes; "
                f"limit is {per_file_limit}"
            )
        if self._downloaded_artifact_bytes + remote_size > total_limit:
            raise RuntimeError(
                f"remote scan artifacts would exceed aggregate limit {total_limit} bytes"
            )

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{local.name}.", suffix=".part", dir=local.parent
        )
        temporary = Path(temporary_name)
        received = 0
        try:
            with (
                self._bounded_operation("SFTP download"),
                os.fdopen(descriptor, "wb") as output,
                sftp.open(remote_path, "rb") as source,
            ):
                while chunk := source.read(64 * 1024):
                    received += len(chunk)
                    if received > per_file_limit:
                        raise RuntimeError(
                            f"remote scan artifact {remote_path} grew beyond "
                            f"the {per_file_limit}-byte limit"
                        )
                    if self._downloaded_artifact_bytes + received > total_limit:
                        raise RuntimeError(
                            f"remote scan artifacts exceed aggregate limit {total_limit} bytes"
                        )
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, local)
            self._downloaded_artifact_bytes += received
        except Exception:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise

    def close(self) -> None:
        if self._sftp is not None:
            self._sftp.close()
            self._sftp = None
        self._client.close()

    def __enter__(self) -> SshSession:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
