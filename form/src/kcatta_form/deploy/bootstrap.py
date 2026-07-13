"""Form-owned password -> key SSH authentication bootstrap.

The scan pipeline authenticates with keys (paramiko, key only). This module
makes the first connection ergonomic for operators who only know a password:

1. Pick / generate a managed ed25519 keypair on the scanner host. Its filename
   combines a readable target label with a digest of the original
   ``(user, host, port)`` identity, so lossy filename sanitization cannot make
   two targets share one key.
2. Try key login. If it works, return that path.
3. Otherwise use the password once to append the public key to the target's
   ``~/.ssh/authorized_keys``, verify key login, then drop the password.

``revoke_key`` is the inverse: it removes exactly the line this tool added.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import paramiko

from ._util import sh_quote, split_user_host
from .ssh import create_ssh_client

CONNECT_TIMEOUT = 10.0


def _sanitize(value: str) -> str:
    # Keep the readable portion single-byte and filesystem-portable; the digest
    # below, not this lossy label, carries the complete Unicode identity.
    return "".join(c if (c.isascii() and (c.isalnum() or c in "-_.")) else "_" for c in value)


def _managed_path_stem(user: str, host: str, port: int) -> str:
    """Collision-resistant filename stem for a managed target credential.

    ``_sanitize`` is intentionally lossy (for example, ``DOMAIN\\user`` and
    ``DOMAIN_user`` sanitize identically). Keep its readable label, but bind the
    filename to the unsanitized logical identity with a full SHA-256 digest.
    Canonical JSON keeps the three typed input fields unambiguous.
    """
    identity = json.dumps([user, host, port], ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    digest = hashlib.sha256(identity).hexdigest()
    # NAME_MAX is commonly 255 bytes. Bound the readable prefix so maximal DNS
    # names still leave room for the digest and `.ed25519` / `.crt` suffixes.
    readable_user = _sanitize(user)[:40]
    readable_host = _sanitize(host)[:80]
    return f"{readable_user}@{readable_host}-{port}-{digest}"


def _config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return Path(base) if base else Path.home() / ".config"


def _ensure_key_dir() -> Path:
    """The managed-keys dir, created/tightened to 0o700 (private to the Form user).

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
    return directory / f"{_managed_path_stem(user, host, port)}.ed25519"


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
            "ssh-keygen",
            "-t",
            "ed25519",
            "-N",
            "",
            "-q",
            "-f",
            str(path),
            "-C",
            f"agent-remote@{user}@{host}",
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
    # multi-tenant Form host can't leak public keys/fingerprints by readdir.
    with contextlib.suppress(OSError):
        _pub_path(path).chmod(0o600)


def _key_auth_succeeds(user: str, host: str, port: int, key: Path) -> bool:
    client = create_ssh_client()
    try:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            key_filename=str(key),
            look_for_keys=False,
            allow_agent=False,
            timeout=5.0,
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

    Password bootstrap, key probes, scans, rotate, and revoke all use the same
    persistent known_hosts configuration from :func:`create_ssh_client`.
    """
    client = create_ssh_client()
    if key is not None:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            key_filename=str(key),
            look_for_keys=False,
            allow_agent=False,
            timeout=CONNECT_TIMEOUT,
        )
    else:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=CONNECT_TIMEOUT,
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
    """Remove the exact public-key identity from ``authorized_keys``.

    Match the algorithm + base64 blob, not the mutable comment or key options.
    Rewrites through a temp file in the same dir and verifies the key blob is
    absent after the atomic rename. Prints ``__removed`` / ``__absent``.
    """
    fields = pub_line.split()
    if len(fields) < 2:
        raise RuntimeError("managed SSH public key is malformed")
    key_type, key_blob = fields[0], fields[1]
    if not re.fullmatch(r"[A-Za-z0-9@._+-]+", key_type) or not re.fullmatch(
        r"[A-Za-z0-9+/=]+", key_blob
    ):
        raise RuntimeError("managed SSH public key contains invalid algorithm/blob characters")
    quoted_type = sh_quote(key_type)
    quoted_blob = sh_quote(key_blob)
    matcher = (
        f"awk -v kt={quoted_type} -v kb={quoted_blob} "
        "'{ for (i=1; i<NF; i++) if ($i == kt && $(i+1) == kb) found=1 } "
        "END { exit(found ? 0 : 1) }'"
    )
    filterer = (
        f"awk -v kt={quoted_type} -v kb={quoted_blob} "
        "'{ drop=0; for (i=1; i<NF; i++) if ($i == kt && $(i+1) == kb) drop=1; "
        "if (!drop) print }'"
    )
    return (
        'f="$HOME/.ssh/authorized_keys"; '
        '[ -f "$f" ] || { echo __absent; exit 0; }; '
        '[ -r "$f" ] || exit 1; '
        f'{matcher} "$f"; rc=$?; '
        'if [ "$rc" -eq 0 ]; then '
        '  tmp=$(mktemp "$f.XXXXXX") || exit 1; '
        '  chmod 600 "$tmp"; '
        f'  {filterer} "$f" > "$tmp" || {{ rm -f "$tmp"; exit 1; }}; '
        # Atomic replace: rename within the same dir so an interrupted revoke can
        # never leave authorized_keys truncated/empty (SSH lockout). mktemp is
        # 0600, matching the file mode.
        '  mv -f "$tmp" "$f" || exit 1; '
        f'  {matcher} "$f"; post_rc=$?; '
        '  if [ "$post_rc" -eq 0 ]; then echo __still_present >&2; exit 1; fi; '
        '  [ "$post_rc" -eq 1 ] || exit "$post_rc"; echo __removed; '
        'elif [ "$rc" -eq 1 ]; then echo __absent; '
        'else exit "$rc"; fi'
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
        raise RuntimeError(f"public key appended but key login still fails on {user}@{host}:{port}")
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
    is proven working, so a failed rotation never locks Form out.
    """
    user, host = split_user_host(target)
    key = default_key_path(user, host, port)
    pub = _pub_path(key)
    if not key.is_file() or not pub.is_file():
        raise RuntimeError(
            f"managed SSH keypair for {user}@{host}:{port} is incomplete; "
            "bootstrap or recover both private and public key files before rotation"
        )
    old_pub_line = pub.read_text(encoding="utf-8").strip()
    if not old_pub_line:
        raise RuntimeError(f"managed SSH public key {pub} is empty; refusing unsafe rotation")

    # Stage the new keypair beside the managed one (same dir → atomic os.replace).
    new_key = key.with_name(key.name + ".new")
    new_pub = _pub_path(new_key)
    old_key_backup = key.with_name(key.name + ".rotate-old")
    old_pub_backup = pub.with_name(pub.name + ".rotate-old")
    if old_key_backup.exists() or old_pub_backup.exists():
        raise RuntimeError(
            f"incomplete prior SSH key rotation backup exists for {user}@{host}:{port}; "
            "recover or remove it before retrying"
        )
    new_key.unlink(missing_ok=True)
    new_pub.unlink(missing_ok=True)
    _generate_keypair(new_key, user, host)

    client: paramiko.SSHClient | None = None
    promoted = False
    try:
        new_pub_line = new_pub.read_text(encoding="utf-8").strip()
        # Authenticate with the OLD key (still in place) when possible, else password.
        client = _authed_session(user, host, port, key, password)
        _out, err, code = _exec(client, _install_pub_cmd(new_pub_line))
        if code != 0:
            raise RuntimeError(f"new authorized_keys install failed (exit {code}): {err.strip()}")

        if not _key_auth_succeeds(user, host, port, new_key):
            # The old credential is still active. Remove the staged remote key so
            # a failed proof does not leave an unmanaged authorized_keys entry.
            with contextlib.suppress(Exception):
                _exec(client, _remove_pub_cmd(new_pub_line))
            raise RuntimeError(
                f"new public key appended but key login still fails on {user}@{host}:{port}"
            )

        # Keep a rollback copy until both the local promotion and remote revoke
        # commit. The new key is proven before either old copy is touched.
        if key.exists():
            shutil.copy2(key, old_key_backup)
        if pub.exists():
            shutil.copy2(pub, old_pub_backup)
        try:
            os.replace(new_key, key)
            os.replace(new_pub, pub)
            promoted = True
        except Exception:
            if old_key_backup.exists():
                os.replace(old_key_backup, key)
            if old_pub_backup.exists():
                os.replace(old_pub_backup, pub)
            with contextlib.suppress(Exception):
                _exec(client, _remove_pub_cmd(new_pub_line))
            raise

        # Only revoke the old remote key after the new managed keypair is both
        # verified and locally active. A cleanup response can be ambiguous (the
        # remote rename may have committed just before the connection dropped),
        # so never roll back or remove the proven new key after this point.
        if old_pub_line and old_pub_line != new_pub_line:
            new_client: paramiko.SSHClient | None = None
            try:
                new_client = _key_session(user, host, port, key)
                _out, err, code = _exec(new_client, _remove_pub_cmd(old_pub_line))
                if code != 0:
                    raise RuntimeError(
                        f"old authorized_keys revoke failed (exit {code}): {err.strip()}"
                    )
            except Exception as cleanup_error:
                raise RuntimeError(
                    "new SSH key is active, but old authorized_keys cleanup failed; "
                    f"recovery copies remain at {old_key_backup} and {old_pub_backup}"
                ) from cleanup_error
            finally:
                if new_client is not None:
                    new_client.close()

        old_key_backup.unlink(missing_ok=True)
        old_pub_backup.unlink(missing_ok=True)
        return key
    except Exception:
        if not promoted:
            new_key.unlink(missing_ok=True)
            new_pub.unlink(missing_ok=True)
        raise
    finally:
        if client is not None:
            client.close()
