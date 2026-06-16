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

import contextlib
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


def _ensure_key_dir() -> Path:
    """The managed-keys dir, created/tightened to 0o700 (private to the analyzer user).

    ``mkdir(mode=…)`` does NOT tighten a pre-existing dir (and ``exist_ok=True``
    skips the mode entirely), so chmod the leaf explicitly — otherwise a dir left
    at the default 0o755 by an earlier version would stay group/world-traversable,
    letting other local users enumerate which user@host:port targets exist.
    """
    directory = _config_dir() / "scdr" / "agent-remote" / "keys"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with contextlib.suppress(OSError):
        directory.chmod(0o700)
    return directory


def default_key_path(user: str, host: str, port: int) -> Path:
    """Managed-key path on the scanner host (created if missing)."""
    directory = _ensure_key_dir()
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
    # ssh-keygen already 0o600s the private key; tighten the .pub too so a
    # multi-tenant analyzer host can't leak public keys/fingerprints by readdir.
    with contextlib.suppress(OSError):
        _pub_path(path).chmod(0o600)


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


def _password_session(
    user: str, host: str, port: int, password: str | None = None, key: Path | None = None
) -> paramiko.SSHClient:
    """Open an SSH session — by password, or by managed key when ``key`` is given.

    A single client-construction point (one host-key policy) shared by the
    password-bootstrap and the key-auth rotate/revoke paths, so there is exactly
    one ``AutoAddPolicy`` site here rather than one per auth mode. AutoAddPolicy is
    the project-wide trust model for SSH (see SECURITY.md — trusted lab/intranet).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if key is not None:
        client.connect(
            hostname=host, port=port, username=user, key_filename=str(key),
            look_for_keys=False, allow_agent=False, timeout=CONNECT_TIMEOUT,
        )
    else:
        client.connect(
            hostname=host, port=port, username=user, password=password,
            look_for_keys=False, allow_agent=False, timeout=CONNECT_TIMEOUT,
        )
    return client


def _key_session(user: str, host: str, port: int, key: Path) -> paramiko.SSHClient:
    """Open a key-authenticated session (delegates to the shared session opener)."""
    return _password_session(user, host, port, key=key)


def _authed_session(
    user: str, host: str, port: int, key: Path, password: str | None
) -> paramiko.SSHClient:
    """Authenticate preferring the managed key, falling back to a one-time password.

    Used by rotate/revoke, which need an authenticated session to edit the
    target's ``authorized_keys``: when the current managed key still works no
    password is needed; otherwise the supplied ``password`` is used once. Raises
    if neither can authenticate.
    """
    if key.exists() and _key_auth_succeeds(user, host, port, key):
        return _key_session(user, host, port, key)
    if password:
        return _password_session(user, host, port, password)
    raise RuntimeError(
        f"cannot authenticate to {user}@{host}:{port}: managed key auth failed "
        "and no password was provided"
    )


def _exec(client: paramiko.SSHClient, command: str) -> tuple[str, str, int]:
    _stdin, stdout, stderr = client.exec_command(command)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    status = stdout.channel.recv_exit_status()
    return out, err, status


def _install_pub_cmd(pub_line: str) -> str:
    """Idempotently append a public key line to the target's authorized_keys."""
    quoted = sh_quote(pub_line)
    return (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
        f"(grep -qxF {quoted} ~/.ssh/authorized_keys || echo {quoted} >> ~/.ssh/authorized_keys)"
    )


def _remove_pub_cmd(pub_line: str) -> str:
    """Remove exactly one public key line from authorized_keys (whole-line match).

    Rewrites through a temp file in the same dir so mode/owner are preserved; only
    our exact entry is touched. Prints ``__removed`` / ``__absent``.
    """
    quoted = sh_quote(pub_line)
    return (
        'f="$HOME/.ssh/authorized_keys"; '
        '[ -f "$f" ] || { echo __absent; exit 0; }; '
        f'if grep -qxF {quoted} "$f"; then '
        '  tmp=$(mktemp "$f.XXXXXX") || exit 1; '
        f'  grep -vxF {quoted} "$f" > "$tmp" || true; '
        '  cat "$tmp" > "$f"; rm -f "$tmp"; echo __removed; '
        'else echo __absent; fi'
    )


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
    install_cmd = _install_pub_cmd(pub_line)
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
    pub = _pub_path(key)
    if not pub.exists():
        # `cred.exists` is gated on the PRIVATE key; a present-private / missing-pub
        # state (manual deletion, interrupted keygen) would otherwise crash here
        # with an opaque FileNotFoundError → 502. Fail with a clear message instead.
        raise RuntimeError(
            f"managed public key {pub} is missing; cannot determine the line to revoke"
        )
    pub_line = pub.read_text(encoding="utf-8").strip()
    if not pub_line:
        raise RuntimeError(f"managed public key {pub} is empty")

    client = _authed_session(user, host, port, key, password)
    try:
        out, err, code = _exec(client, _remove_pub_cmd(pub_line))
    finally:
        client.close()
    if code != 0:
        raise RuntimeError(f"revoke command failed (exit {code}): {err.strip()}")
    return "__removed" in out


def can_authenticate(target: str, port: int, identity: Path | None = None) -> bool:
    """True if the managed (or ``identity``) key can currently log into ``user@host:port``.

    Used by the credential-management "test connectivity" action: resolves the
    same key path the scan pipeline would use and probes a key-only login.
    """
    user, host = split_user_host(target)
    key = identity if identity is not None else default_key_path(user, host, port)
    if not key.exists():
        return False
    return _key_auth_succeeds(user, host, port, key)


def key_fingerprint(key: Path) -> str | None:
    """SHA256 fingerprint of the managed public key (e.g. ``SHA256:…``), or None.

    Reads ``<key>.pub`` via ``ssh-keygen -lf``. Returns None when the public key is
    absent or ssh-keygen is unavailable — a missing fingerprint is "unknown", not
    an error (the key may still be usable; the UI just shows it as unverified).
    """
    pub = _pub_path(key)
    if not pub.exists():
        return None
    try:
        # Pin -E sha256 so the format is deterministic regardless of the host's
        # FingerprintHash default (schema/UI promise a SHA256 fingerprint).
        result = subprocess.run(
            ["ssh-keygen", "-lf", str(pub), "-E", "sha256"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    # Output: "<bits> SHA256:<hash> <comment> (<TYPE>)" — pull the hash token.
    for token in result.stdout.split():
        if token.startswith("SHA256:"):
            return token
    return None


def rotate_key(target: str, port: int, password: str | None = None) -> Path:
    """Rotate the tool-managed SSH key for ``user@host:port``; return the key path.

    Generates a fresh keypair, installs the new public key — authenticating with
    the *current* managed key when it still works (no password needed), else a
    one-time ``password`` — verifies the new key logs in, removes the old public
    key line from the target's ``authorized_keys``, then atomically swaps the new
    keypair into the managed path. The old key is left untouched until the new one
    is proven working, so a failed rotation never locks the analyzer out.
    """
    user, host = split_user_host(target)
    key = default_key_path(user, host, port)
    pub = _pub_path(key)
    old_pub_line = pub.read_text(encoding="utf-8").strip() if pub.exists() else ""

    # Stage the new keypair beside the managed one (same dir → atomic os.replace).
    new_key = key.with_name(key.name + ".new")
    new_pub = _pub_path(new_key)
    new_key.unlink(missing_ok=True)
    new_pub.unlink(missing_ok=True)
    _generate_keypair(new_key, user, host)

    try:
        new_pub_line = new_pub.read_text(encoding="utf-8").strip()
        # Authenticate with the OLD key (still in place) when possible, else password.
        client = _authed_session(user, host, port, key, password)
        try:
            _out, err, code = _exec(client, _install_pub_cmd(new_pub_line))
            if code != 0:
                raise RuntimeError(
                    f"new authorized_keys install failed (exit {code}): {err.strip()}"
                )
            # Drop the superseded key line (best-effort; absence is fine).
            if old_pub_line and old_pub_line != new_pub_line:
                _exec(client, _remove_pub_cmd(old_pub_line))
        finally:
            client.close()

        if not _key_auth_succeeds(user, host, port, new_key):
            raise RuntimeError(
                f"new public key appended but key login still fails on {user}@{host}:{port}"
            )

        # Promote the new keypair into the managed path. Each os.replace is atomic;
        # the pair is not, so a crash strictly between the two leaves key=new /
        # pub=old. That window is two syscalls wide and self-heals on the next
        # rotation (which regenerates both); revoke also guards a missing pub above.
        os.replace(new_key, key)
        os.replace(new_pub, pub)
        return key
    except Exception:
        new_key.unlink(missing_ok=True)
        new_pub.unlink(missing_ok=True)
        raise
