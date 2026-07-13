r"""Form-owned WinRM client-certificate bootstrap — the WinRM analog of SSH ``bootstrap``.

SSH gets passwordless, durable auth by installing a managed key in the target's
``authorized_keys`` (see :mod:`.bootstrap`). WinRM has no ``authorized_keys``; the
equivalent "bootstrap once with a one-time password, then connect with no stored
password" mechanism is **TLS client-certificate auth**:

1. Generate a managed client certificate on the Form host. As with SSH managed
   keys, its filename includes a digest of the original target identity so
   filename sanitization cannot alias two accounts.
2. Over a one-time password (NTLM) session: enable Certificate auth, import the
   public cert into the target's trust stores, and create a
   ``WSMan:\localhost\ClientCertificate`` mapping from the cert to the local
   account. The password is then discarded — never persisted.
3. Subsequent scans authenticate with the cert (``transport=ssl``), no password.

``revoke_cert`` is the inverse. ``rotate_cert`` regenerates + re-maps.

.. warning::
   The target-side PowerShell here (cert import / WSMan ClientCertificate mapping /
   Certificate-auth enablement) is written to Microsoft's documented recipe but is
   **NOT validated against a real Windows host in this repo** — unit tests mock the
   WinRM session. An **HTTPS WinRM listener is a prerequisite** (cert auth is
   HTTPS-only); this module verifies one exists and errors clearly if not, rather
   than provisioning it. Validate end-to-end on a real target before relying on it.

.. warning::
   **Password exposure on the target.** The mapping step needs the local account's
   credential (``New-Item WSMan:\\…\\ClientCertificate -Credential``), so the
   one-time password is interpolated into the PowerShell that ``pywinrm`` dispatches
   via ``powershell -EncodedCommand <base64(script)>``. That base64 blob — trivially
   reversible — becomes the literal ``powershell.exe`` command line on the TARGET, so
   the password is captured by the target's own process-creation auditing (Event 4688
   / Sysmon 1 / EDR) during bootstrap and rotate. Form never persists or
   logs it. Mitigation: use a **dedicated, low-privilege bootstrap account and rotate
   its password afterward**, and control audit-log retention on the target.

.. warning::
   WinRM HTTPS server certificates are validated by default. Setting
   ``FORM_WINRM_SKIP_CERT_CHECK=true`` disables that protection for self-signed
   lab targets; on an untrusted Form→target path a MITM could capture or relay the
   password-bearing NTLMv2 exchange. Keep the default outside a controlled lab.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
from pathlib import Path

from .bootstrap import _config_dir, _managed_path_stem  # shared path helpers (XDG-aware)
from .winrm import WinRmOptions, WinRmSession, _escape_ps

# Charset allowed in a WinRM identity (user / host) before it is interpolated into
# an openssl ``-subj`` / PowerShell literal. Covers ``DOMAIN\user`` and DNS hosts;
# rejects anything that could break openssl subject parsing or PS quoting.
_IDENTITY_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@\\")

# msUPN otherName OID — the SAN that a WSMan ClientCertificate mapping matches on.
_MS_UPN_OID = "1.3.6.1.4.1.311.20.2.3"


def _validate_identity(value: str, kind: str) -> str:
    if not value or any(c not in _IDENTITY_OK for c in value):
        raise ValueError(f"unsupported character in WinRM {kind} {value!r}")
    return value


def _cert_dir() -> Path:
    """The managed WinRM certs dir, created/tightened to 0o700."""
    directory = _config_dir() / "scdr" / "agent-remote" / "winrm-certs"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with contextlib.suppress(OSError):
        directory.chmod(0o700)
    return directory


def managed_cert_paths(target: str, port: int) -> tuple[Path, Path]:
    """Deterministic ``(cert.crt, key.key)`` paths for ``user@host`` + ``port``."""
    user, host = _split(target)
    directory = _cert_dir()
    stem = _managed_path_stem(user, host, port)
    return directory / f"{stem}.crt", directory / f"{stem}.key"


def _split(target: str) -> tuple[str, str]:
    user, sep, host = target.rpartition("@")
    if not sep or not user or not host:
        raise ValueError(f"target must be user@host, got {target!r}")
    return _validate_identity(user, "user"), _validate_identity(host, "host")


def _upn(user: str, host: str) -> str:
    """The cert's msUPN SAN / mapping subject (``user@host``)."""
    return f"{user}@{host}"


def _generate_client_cert(cert: Path, key: Path, user: str, host: str) -> None:
    """Generate a self-signed client cert (UPN SAN + clientAuth EKU) via openssl."""
    cert.parent.mkdir(parents=True, exist_ok=True)
    upn = _upn(user, host)
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "3650",
            "-subj",
            f"/CN={user}",
            "-addext",
            f"subjectAltName=otherName:{_MS_UPN_OID};UTF8:{upn}",
            "-addext",
            "extendedKeyUsage=clientAuth",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"openssl client-cert generation failed: {result.stderr.strip()}")
    with contextlib.suppress(OSError):
        key.chmod(0o600)
        cert.chmod(0o600)


def _atomic_restore(source: Path, destination: Path) -> None:
    """Restore a credential file atomically while retaining the recovery copy."""
    staged = destination.with_name(destination.name + ".restore")
    staged.unlink(missing_ok=True)
    shutil.copy2(source, staged)
    os.replace(staged, destination)


def cert_fingerprint(cert: Path) -> str | None:
    """SHA256 fingerprint of the cert (``SHA256:AA:BB:…``), or None if unresolvable."""
    if not cert.exists():
        return None
    out = _openssl_fingerprint(cert, "sha256")
    return f"SHA256:{out}" if out else None


def cert_thumbprint(cert: Path) -> str | None:
    """Windows thumbprint (SHA1, uppercase hex, no separators), or None."""
    out = _openssl_fingerprint(cert, "sha1")
    return out.replace(":", "").upper() if out else None


def _openssl_fingerprint(cert: Path, alg: str) -> str | None:
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", f"-{alg}"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    # Output: "sha256 Fingerprint=AA:BB:..." — take the part after '='.
    _, _, value = result.stdout.partition("=")
    return value.strip() or None


# --------------------------------------------------------------- target-side PS


def _ps_check_https_listener() -> str:
    return (
        "$l = Get-ChildItem WSMan:\\localhost\\Listener -ErrorAction SilentlyContinue | "
        "Where-Object { ($_.Keys -join ';') -match 'Transport=HTTPS' }; "
        "if ($l) { Write-Output __https_ok } else { Write-Output __no_https }"
    )


def _ps_enable_cert_auth() -> str:
    return "Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Certificate -Value $true -Force"


def _ps_import_cert(remote_cert: str) -> str:
    q = f"'{_escape_ps(remote_cert)}'"
    return (
        f"$c = Import-Certificate -FilePath {q} -CertStoreLocation Cert:\\LocalMachine\\Root; "
        f"Import-Certificate -FilePath {q} -CertStoreLocation Cert:\\LocalMachine\\TrustedPeople "
        "| Out-Null; "
        'Write-Output "__thumb=$($c.Thumbprint)"'
    )


def _ps_create_mapping(upn: str, user: str, password: str, thumbprint: str) -> str:
    cred_cls = "System.Management.Automation.PSCredential"
    return (
        f"$sec = ConvertTo-SecureString '{_escape_ps(password)}' -AsPlainText -Force; "
        f"$cred = New-Object {cred_cls}('{_escape_ps(user)}', $sec); "
        f"New-Item -Path WSMan:\\localhost\\ClientCertificate -Subject '{_escape_ps(upn)}' "
        f"-URI * -Issuer '{_escape_ps(thumbprint)}' -Credential $cred -Force | Out-Null; "
        "Write-Output __mapped"
    )


def _ps_remove_mapping(upn: str, thumbprint: str) -> str:
    escaped_upn = _escape_ps(upn)
    escaped_thumb = _escape_ps(thumbprint)
    mapping_query = (
        "Get-ChildItem WSMan:\\localhost\\ClientCertificate -ErrorAction Stop | "
        f"Where-Object {{ $_.Subject -eq '{escaped_upn}' -and "
        f"$_.Issuer -eq '{escaped_thumb}' }}"
    )
    cert_query = (
        "Get-ChildItem Cert:\\LocalMachine\\Root, Cert:\\LocalMachine\\TrustedPeople "
        "-ErrorAction Stop | "
        f"Where-Object {{ $_.Thumbprint -eq '{escaped_thumb}' }}"
    )
    return (
        "$ErrorActionPreference = 'Stop'; try { "
        f"@({mapping_query}) | Remove-Item -Force -Recurse -ErrorAction Stop; "
        f"@({cert_query}) | Remove-Item -Force -ErrorAction Stop; "
        f"$mappingLeft = @({mapping_query}).Count; "
        f"$certLeft = @({cert_query}).Count; "
        "if ($mappingLeft -eq 0 -and $certLeft -eq 0) { Write-Output __revoked } "
        "else { Write-Error 'WinRM credential still present after revoke'; exit 1 } "
        "} catch { Write-Error $_; exit 1 }"
    )


# ----------------------------------------------------------------- public API


def _password_session(target: str, port: int, password: str, skip_cert_check: bool) -> WinRmSession:
    user, host = _split(target)
    return WinRmSession(
        WinRmOptions(
            user=user, host=host, password=password, port=port, skip_cert_check=skip_cert_check
        )
    )


def _cert_session(
    target: str, port: int, cert: Path, key: Path, skip_cert_check: bool
) -> WinRmSession:
    user, host = _split(target)
    return WinRmSession(
        WinRmOptions(
            user=user,
            host=host,
            port=port,
            cert_pem=cert,
            cert_key_pem=key,
            skip_cert_check=skip_cert_check,
        )
    )


def ensure_cert_auth(
    target: str,
    port: int,
    password: str,
    skip_cert_check: bool = False,
) -> tuple[Path, Path]:
    """Bootstrap passwordless cert auth for ``user@host:port``; return ``(cert, key)``.

    Generates the managed cert if missing, then over a one-time password session
    enables Certificate auth, imports the cert, and maps it to the local account.
    The ``password`` is used once and never persisted by this function.
    """
    user, host = _split(target)
    cert, key = managed_cert_paths(target, port)
    if not cert.exists() or not key.exists():
        _generate_client_cert(cert, key, user, host)
    _install_cert_auth(target, port, password, cert, key, skip_cert_check)
    return cert, key


def _install_cert_auth(
    target: str,
    port: int,
    password: str,
    cert: Path,
    key: Path,
    skip_cert_check: bool,
) -> None:
    """Install and prove an explicit cert/key pair without changing managed paths."""
    user, host = _split(target)
    thumb = cert_thumbprint(cert)
    if not thumb:
        raise RuntimeError(f"could not compute thumbprint for {cert} (is openssl installed?)")

    session = _password_session(target, port, password, skip_cert_check)
    remote_cert = "$env:TEMP\\kcatta-winrm-client.cer"
    listener = session.exec(_ps_check_https_listener())
    if "__no_https" in _out(listener):
        raise RuntimeError(
            f"no HTTPS WinRM listener on {host}:{port} — cert auth is HTTPS-only. "
            "Provision one first, e.g.: winrm quickconfig -transport:https "
            "(or New-Item WSMan:\\localhost\\Listener -Transport HTTPS ...)."
        )
    session.exec(_ps_enable_cert_auth())
    session.upload_file(cert, remote_cert)
    imported = session.exec(_ps_import_cert(remote_cert))
    if "__thumb=" not in _out(imported):
        raise RuntimeError(f"failed to import client cert on {host}: {_err(imported)}")
    mapped = session.exec(_ps_create_mapping(_upn(user, host), user, password, thumb))
    if "__mapped" not in _out(mapped):
        raise RuntimeError(f"failed to create ClientCertificate mapping on {host}: {_err(mapped)}")

    if not _can_authenticate_cert_files(target, port, cert, key, skip_cert_check):
        raise RuntimeError(
            f"cert mapping created but cert login still fails on {host}:{port} "
            "(check the local account, UPN mapping, and HTTPS listener cert)"
        )


def can_authenticate_cert(target: str, port: int, skip_cert_check: bool = False) -> bool:
    """True if the managed client cert can currently authenticate over WinRM."""
    cert, key = managed_cert_paths(target, port)
    if not cert.exists() or not key.exists():
        return False
    return _can_authenticate_cert_files(target, port, cert, key, skip_cert_check)


def _can_authenticate_cert_files(
    target: str, port: int, cert: Path, key: Path, skip_cert_check: bool
) -> bool:
    """Probe a specific pair, including rotation staging files."""
    try:
        session = _cert_session(target, port, cert, key, skip_cert_check)
        return "__ok" in _out(session.exec("Write-Output __ok"))
    except Exception:
        return False


def rotate_cert(
    target: str, port: int, password: str | None = None, skip_cert_check: bool = False
) -> tuple[Path, Path]:
    """Rotate the managed WinRM cert with staged proof and rollback.

    Unlike SSH, WinRM has no passwordless rotation: creating the new
    ClientCertificate mapping needs the local account's password, so one must be
    provided. The old local pair remains untouched until the staged pair has been
    installed and authenticated. Failed installation restores the old mapping.
    """
    if not password:
        raise RuntimeError(
            "WinRM cert rotation requires the target account password "
            "(creating the ClientCertificate mapping needs it; there is no key-reuse path)"
        )
    cert, key = managed_cert_paths(target, port)
    if not cert.exists() or not key.exists():
        raise RuntimeError(
            f"managed WinRM cert/key for {target}:{port} is missing; bootstrap it before rotation"
        )
    user, host = _split(target)
    new_cert = cert.with_name(cert.name + ".new")
    new_key = key.with_name(key.name + ".new")
    old_cert_backup = cert.with_name(cert.name + ".rotate-old")
    old_key_backup = key.with_name(key.name + ".rotate-old")
    if old_cert_backup.exists() or old_key_backup.exists():
        raise RuntimeError(
            f"incomplete prior WinRM cert rotation backup exists for {target}:{port}; "
            "recover or remove it before retrying"
        )
    new_cert.unlink(missing_ok=True)
    new_key.unlink(missing_ok=True)
    _generate_client_cert(new_cert, new_key, user, host)
    shutil.copy2(cert, old_cert_backup)
    shutil.copy2(key, old_key_backup)

    try:
        try:
            _install_cert_auth(target, port, password, new_cert, new_key, skip_cert_check)
        except Exception as install_error:
            try:
                _install_cert_auth(
                    target,
                    port,
                    password,
                    old_cert_backup,
                    old_key_backup,
                    skip_cert_check,
                )
            except Exception as rollback_error:
                raise RuntimeError(
                    f"new WinRM cert installation failed and old mapping rollback also failed: "
                    f"{rollback_error}"
                ) from install_error
            old_cert_backup.unlink(missing_ok=True)
            old_key_backup.unlink(missing_ok=True)
            raise

        try:
            os.replace(new_key, key)
            os.replace(new_cert, cert)
        except Exception as promote_error:
            rollback_error: Exception | None = None
            try:
                _install_cert_auth(
                    target,
                    port,
                    password,
                    old_cert_backup,
                    old_key_backup,
                    skip_cert_check,
                )
            except Exception as exc:
                rollback_error = exc
            finally:
                _atomic_restore(old_key_backup, key)
                _atomic_restore(old_cert_backup, cert)
            if rollback_error is not None:
                raise RuntimeError(
                    "local WinRM cert promotion failed and old mapping rollback also failed: "
                    f"{rollback_error}"
                ) from promote_error
            old_key_backup.unlink(missing_ok=True)
            old_cert_backup.unlink(missing_ok=True)
            raise

        old_thumb = cert_thumbprint(old_cert_backup)
        if not old_thumb:
            raise RuntimeError(
                f"could not compute old WinRM cert thumbprint from {old_cert_backup}"
            )
        cleanup_session = _cert_session(target, port, cert, key, skip_cert_check)
        cleanup = cleanup_session.exec(_ps_remove_mapping(_upn(user, host), old_thumb))
        if getattr(cleanup, "status_code", 0) != 0 or "__revoked" not in _out(cleanup):
            raise RuntimeError(
                "new WinRM cert is active, but the old mapping/certificate cleanup failed; "
                f"recovery copies remain at {old_cert_backup} and {old_key_backup}"
            )

        old_cert_backup.unlink()
        old_key_backup.unlink()
        return cert, key
    finally:
        new_cert.unlink(missing_ok=True)
        new_key.unlink(missing_ok=True)
        # Once the new pair is promoted it remains active even if old-cert cleanup
        # reports failure. Rolling back after an ambiguous remote response could
        # itself lock out a valid new mapping; retained backups make that state
        # explicit and recoverable. Failed rollback likewise retains its copies.


def revoke_cert(
    target: str, port: int, password: str | None = None, skip_cert_check: bool = False
) -> bool:
    """Remove the target's ClientCertificate mapping + trusted cert, delete local files.

    Authenticates with the still-valid managed cert when possible (no password),
    else falls back to the supplied ``password``. Returns True if the remote
    teardown ran.
    """
    user, host = _split(target)
    cert, key = managed_cert_paths(target, port)
    thumb = cert_thumbprint(cert) if cert.exists() else None
    if not thumb:
        raise RuntimeError(f"managed cert {cert} is missing; cannot determine what to revoke")

    if can_authenticate_cert(target, port, skip_cert_check=skip_cert_check):
        session = _cert_session(target, port, cert, key, skip_cert_check)
    elif password:
        session = _password_session(target, port, password, skip_cert_check)
    else:
        raise RuntimeError(
            f"cannot authenticate to {host}:{port} to revoke: "
            "cert auth failed and no password given"
        )
    result = session.exec(_ps_remove_mapping(_upn(user, host), thumb))
    if getattr(result, "status_code", 0) != 0 or "__revoked" not in _out(result):
        raise RuntimeError(
            f"remote WinRM credential revoke did not reach the absent postcondition: {_err(result)}"
        )
    revoked = True
    _delete_cert_files(cert, key)
    return revoked


def _delete_cert_files(cert: Path, key: Path) -> bool:
    deleted = False
    for path in (cert, key):
        if path.exists():
            path.unlink()
            deleted = True
    return deleted


def _out(resp) -> str:
    return (
        resp.std_out.decode("utf-8", "replace")
        if isinstance(resp.std_out, bytes)
        else str(resp.std_out)
    )


def _err(resp) -> str:
    data = getattr(resp, "std_err", b"")
    return (data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)).strip()
