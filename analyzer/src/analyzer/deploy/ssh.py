"""OpenSSH-over-paramiko transport for remote scans.

One :class:`SshSession` keeps a single TCP connection (paramiko ``Transport``)
and opens a fresh channel per command / SFTP transfer — the same "one
connection, many channels" multiplexing the former Rust pipeline got from
OpenSSH ``ControlMaster``. Key auth only; the one-shot password bootstrap that
installs the managed key lives in :mod:`analyzer.deploy.bootstrap`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import paramiko

DEFAULT_CONNECT_TIMEOUT = 15.0


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
    ) -> None:
        self.host = host
        self.user = user
        self._client = paramiko.SSHClient()
        # AutoAddPolicy == StrictHostKeyChecking=no: trust whatever host key is
        # presented (incl. changed keys); acceptable for the trusted lab pipeline only.
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            hostname=host,
            port=port,
            username=user,
            key_filename=str(key_path),
            look_for_keys=False,
            allow_agent=False,
            timeout=connect_timeout,
        )
        self._sftp: paramiko.SFTPClient | None = None

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}"

    def exec(self, command: str) -> CommandOutput:
        """Run ``command`` over a new channel; capture stdout/stderr/exit."""
        _stdin, stdout, stderr = self._client.exec_command(command)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        status = stdout.channel.recv_exit_status()
        return CommandOutput(stdout=out, stderr=err, status=status)

    def _sftp_client(self) -> paramiko.SFTPClient:
        if self._sftp is None:
            self._sftp = self._client.open_sftp()
        return self._sftp

    def upload(self, local: Path, remote_path: str) -> None:
        """Upload a local file to ``remote_path`` on the target."""
        self._sftp_client().put(str(local), remote_path)

    def download(self, remote_path: str, local: Path) -> None:
        """Download ``remote_path`` from the target to ``local``."""
        local.parent.mkdir(parents=True, exist_ok=True)
        self._sftp_client().get(remote_path, str(local))

    def close(self) -> None:
        if self._sftp is not None:
            self._sftp.close()
            self._sftp = None
        self._client.close()

    def __enter__(self) -> SshSession:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
