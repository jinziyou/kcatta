"""Password -> key SSH authentication bootstrap.

The scan pipeline authenticates with keys (paramiko, key only). This module
makes the first connection ergonomic for operators who only know a password:

1. Pick / generate a managed ed25519 keypair on the scanner host
   (``~/.config/scdr/agent-remote/keys/<user>@<host>-<port>.ed25519`` — the
   same path the former Rust tool used, so existing installs keep working).
2. Try key login. If it works, return that path.
3. Otherwise use the password once to append the public key to the target's
   ``~/.ssh/authorized_keys``, verify key login, then drop the password.

``revoke_key`` is the inverse: it removes exactly the line this tool added.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import paramiko

from ._util import sh_quote, split_user_host

CONNECT_TIMEOUT = 10.0


def _sanitize(value: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in value)


def _config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return Path(base) if base else Path.home() / ".config"


def default_key_path(user: str, host: str, port: int) -> Path:
    """Managed-key path on the scanner host (created if missing)."""
    directory = _config_dir() / "scdr" / "agent-remote" / "keys"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{_sanitize(user)}@{_sanitize(host)}-{port}.ed25519"


def managed_key_path(target: str, port: int) -> Path:
    """Resolve the tool-managed private-key path for ``user@host`` + ``port``."""
    user, host = split_user_host(target)
    return default_key_path(user, host, port)


def _pub_path(key: Path) -> Path:
    # ssh-keygen appends `.pub` (it does not replace the extension).
    return key.with_name(key.name + ".pub")


def _generate_keypair(path: Path, user: str, host: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "ssh-keygen", "-t", "ed25519", "-N", "", "-q",
            "-f", str(path), "-C", f"agent-remote@{user}@{host}",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ssh-keygen failed (is openssh-client installed?): {result.stderr.strip()}"
        )


def _key_auth_succeeds(user: str, host: str, port: int, key: Path) -> bool:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=user, key_filename=str(key),
            look_for_keys=False, allow_agent=False, timeout=5.0,
        )
        return True
    except Exception:
        return False
    finally:
        client.close()


def _password_session(user: str, host: str, port: int, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host, port=port, username=user, password=password,
        look_for_keys=False, allow_agent=False, timeout=CONNECT_TIMEOUT,
    )
    return client


def _exec(client: paramiko.SSHClient, command: str) -> tuple[str, str, int]:
    _stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    status = stdout.channel.recv_exit_status()
    return out, err, status


def ensure_key_auth(
    target: str,
    port: int,
    identity: Path | None = None,
    password: str | None = None,
) -> Path:
    """Ensure key-based login works against ``user@host:port``; return the key path.

    Installs the managed public key over a one-shot password session when key
    auth is not yet set up.
    """
    user, host = split_user_host(target)
    key = identity if identity is not None else default_key_path(user, host, port)
    pub_key = _pub_path(key)

    if not key.exists():
        _generate_keypair(key, user, host)
    elif not pub_key.exists():
        raise RuntimeError(f"private key {key} exists but {pub_key} is missing")

    if _key_auth_succeeds(user, host, port, key):
        return key

    if not password:
        raise RuntimeError(
            f"key authentication failed for {user}@{host}:{port} and no password "
            "provided (pass --ssh-password / --ssh-password-stdin / set SCDR_SSH_PASSWORD)"
        )

    pub_line = pub_key.read_text(encoding="utf-8").strip()
    quoted = sh_quote(pub_line)
    install_cmd = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
        f"(grep -qxF {quoted} ~/.ssh/authorized_keys || echo {quoted} >> ~/.ssh/authorized_keys)"
    )
    client = _password_session(user, host, port, password)
    try:
        _out, err, code = _exec(client, install_cmd)
    finally:
        client.close()
    if code != 0:
        raise RuntimeError(f"authorized_keys install failed (exit {code}): {err.strip()}")

    if not _key_auth_succeeds(user, host, port, key):
        raise RuntimeError(
            f"public key appended but key login still fails on {user}@{host}:{port}"
        )
    return key


def revoke_key(
    target: str,
    port: int,
    identity: Path | None = None,
    password: str | None = None,
) -> bool:
    """Remove exactly the managed public key line from the target's
    ``authorized_keys``. Returns ``True`` if a line was removed, ``False`` if
    it was already absent."""
    user, host = split_user_host(target)
    key = identity if identity is not None else default_key_path(user, host, port)
    pub_line = _pub_path(key).read_text(encoding="utf-8").strip()
    if not pub_line:
        raise RuntimeError(f"managed public key {_pub_path(key)} is empty")

    if key.exists() and _key_auth_succeeds(user, host, port, key):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host, port=port, username=user, key_filename=str(key),
            look_for_keys=False, allow_agent=False, timeout=CONNECT_TIMEOUT,
        )
    elif password:
        client = _password_session(user, host, port, password)
    else:
        raise RuntimeError(
            f"cannot authenticate to {user}@{host}:{port} to revoke: managed key auth "
            "failed and no password provided"
        )

    quoted = sh_quote(pub_line)
    # Whole-line fixed-string match; rewrite through a temp file in the same dir
    # so the file keeps its mode/owner. Only our exact entry is touched.
    remove_cmd = (
        'f="$HOME/.ssh/authorized_keys"; '
        '[ -f "$f" ] || { echo __absent; exit 0; }; '
        f'if grep -qxF {quoted} "$f"; then '
        '  tmp=$(mktemp "$f.XXXXXX") || exit 1; '
        f'  grep -vxF {quoted} "$f" > "$tmp" || true; '
        '  cat "$tmp" > "$f"; rm -f "$tmp"; echo __removed; '
        'else echo __absent; fi'
    )
    try:
        out, err, code = _exec(client, remove_cmd)
    finally:
        client.close()
    if code != 0:
        raise RuntimeError(f"revoke command failed (exit {code}): {err.strip()}")
    return "__removed" in out
