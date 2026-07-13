"""Runtime wiring for Form's online Agent CA and identity service."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import stat
import tempfile
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from .agent_identity_store import AgentIdentityRepository
from .agent_pki import (
    AgentCertificateAuthority,
    AgentCertificateAuthorityError,
    AgentIdentityService,
)
from .public_url import normalize_public_origin

_PROCESS_LOCK = threading.Lock()
logger = logging.getLogger("kcatta_form.agent_runtime")

DEFAULT_SERVER_CERTIFICATE_CHECK_SECONDS = 6 * 60 * 60
MAX_SERVER_CERTIFICATE_CHECK_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class AgentRuntimePaths:
    """Explicit separation between public TLS material and the CA signing key."""

    ca_certificate: Path
    ca_private_key: Path
    tls_directory: Path

    @property
    def server_current(self) -> Path:
        return self.tls_directory / "current"

    @property
    def server_certificate(self) -> Path:
        return self.server_current / "server-cert.pem"

    @property
    def server_private_key(self) -> Path:
        return self.server_current / "server-key.pem"

    @classmethod
    def from_env(cls) -> AgentRuntimePaths:
        private_directory = os.getenv("FORM_AGENT_PKI_DIR", "").strip()
        tls_directory = os.getenv("FORM_AGENT_TLS_DIR", "").strip()
        if not private_directory or not tls_directory:
            raise RuntimeError(
                "FORM_AGENT_PKI_DIR and FORM_AGENT_TLS_DIR are required when Agent identity "
                "management is enabled"
            )
        private = Path(private_directory)
        public = Path(tls_directory)
        return cls(
            ca_certificate=public / "ca-cert.pem",
            ca_private_key=private / "ca-key.pem",
            tls_directory=public,
        )


def agent_identity_enabled(auth_mode: str) -> bool:
    raw = os.getenv("FORM_AGENT_IDENTITY_ENABLED")
    if raw is None or not raw.strip():
        return auth_mode in {"mixed", "mtls"}
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise AgentCertificateAuthorityError(f"Agent PKI path is not a real directory: {path}")
    if metadata.st_mode & 0o077:
        path.chmod(0o700)


def _install_secret(path: Path, content: str, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content.encode("ascii"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _server_material_is_valid(
    paths: AgentRuntimePaths,
    server_name: str,
    required_sans: list[str],
) -> bool:
    try:
        certificate_metadata = paths.server_certificate.lstat()
        key_metadata = paths.server_private_key.lstat()
        if not stat.S_ISREG(certificate_metadata.st_mode) or not stat.S_ISREG(key_metadata.st_mode):
            return False
        if stat.S_ISLNK(certificate_metadata.st_mode) or stat.S_ISLNK(key_metadata.st_mode):
            return False
        certificate = x509.load_pem_x509_certificate(paths.server_certificate.read_bytes())
        authority = x509.load_pem_x509_certificate(paths.ca_certificate.read_bytes())
        private_key = serialization.load_pem_private_key(
            paths.server_private_key.read_bytes(), password=None
        )
        cert_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_public != key_public:
            return False
        if certificate.issuer != authority.subject:
            return False
        authority.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
        now = datetime.now(UTC)
        if not (certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc):
            return False
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in usage:
            return False
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = set(names.get_values_for_type(x509.DNSName))
        ip_names = {str(value) for value in names.get_values_for_type(x509.IPAddress)}
        for value in [server_name, *required_sans]:
            normalized = value.strip()
            try:
                if str(ipaddress.ip_address(normalized)) not in ip_names:
                    return False
                continue
            except ValueError:
                pass
            wildcard = normalized.startswith("*.")
            idna_input = normalized[2:] if wildcard else normalized
            ascii_name = idna_input.encode("idna").decode("ascii")
            expected = f"*.{ascii_name}" if wildcard else ascii_name
            if expected not in dns_names:
                return False
        return True
    except (OSError, TypeError, ValueError, InvalidSignature, x509.ExtensionNotFound):
        return False


def _server_material_expires_within(
    paths: AgentRuntimePaths,
    remaining: timedelta,
) -> bool:
    try:
        certificate = x509.load_pem_x509_certificate(paths.server_certificate.read_bytes())
    except (OSError, ValueError):
        return True
    return certificate.not_valid_after_utc - datetime.now(UTC) <= remaining


def _validate_current_generation(paths: AgentRuntimePaths) -> None:
    current = paths.server_current
    if not current.exists() and not current.is_symlink():
        return
    try:
        metadata = current.lstat()
        target = os.readlink(current)
    except OSError as exc:
        raise AgentCertificateAuthorityError(
            f"cannot inspect Agent TLS current generation: {current}"
        ) from exc
    if not stat.S_ISLNK(metadata.st_mode):
        raise AgentCertificateAuthorityError(
            f"Agent TLS current generation must be a symlink: {current}"
        )
    target_path = Path(target)
    if (
        target_path.is_absolute()
        or len(target_path.parts) != 1
        or not target.startswith("generation-")
    ):
        raise AgentCertificateAuthorityError(
            f"Agent TLS current generation has an unsafe target: {target!r}"
        )
    generation = paths.tls_directory / target
    try:
        generation_metadata = generation.lstat()
    except FileNotFoundError as exc:
        raise AgentCertificateAuthorityError(
            f"Agent TLS current generation is missing: {generation}"
        ) from exc
    if stat.S_ISLNK(generation_metadata.st_mode) or not stat.S_ISDIR(generation_metadata.st_mode):
        raise AgentCertificateAuthorityError(
            f"Agent TLS generation is not a real directory: {generation}"
        )


def _publish_server_generation(
    paths: AgentRuntimePaths,
    certificate_pem: str,
    private_key_pem: str,
) -> None:
    """Publish a cert/key pair through one atomic ``current`` symlink switch."""

    generation_name = f"generation-{uuid.uuid4().hex}"
    generation = paths.tls_directory / generation_name
    generation.mkdir(mode=0o700)
    try:
        _install_secret(generation / "server-key.pem", private_key_pem, 0o600)
        _install_secret(generation / "server-cert.pem", certificate_pem, 0o644)
        temporary_link = paths.tls_directory / f".current-{uuid.uuid4().hex}"
        os.symlink(generation_name, temporary_link)
        try:
            os.replace(temporary_link, paths.server_current)
            directory_fd = os.open(paths.tls_directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary_link.unlink(missing_ok=True)
    except Exception:
        # This directory was never reachable through ``current`` when
        # publication failed, so removing only these newly-created files cannot
        # disturb a running listener's previous generation.
        for name in ("server-cert.pem", "server-key.pem"):
            (generation / name).unlink(missing_ok=True)
        with suppress(OSError):
            generation.rmdir()
        raise


def ensure_agent_server_certificate(
    service: AgentIdentityService,
    paths: AgentRuntimePaths,
) -> None:
    """Create the dedicated listener leaf once; never hide partial/corrupt state."""
    agent_public_url = os.getenv("FORM_AGENT_PUBLIC_URL", "").strip()
    if agent_public_url:
        agent_public_url = normalize_public_origin(
            agent_public_url,
            label="FORM_AGENT_PUBLIC_URL",
        )
    server_name = os.getenv("FORM_AGENT_TLS_SERVER_NAME", "").strip()
    if not server_name:
        public_url = agent_public_url or os.getenv("FORM_PUBLIC_URL", "").strip()
        server_name = urlsplit(public_url).hostname or "form-agent"
    sans = [
        value.strip() for value in os.getenv("FORM_AGENT_TLS_SANS", "").split(",") if value.strip()
    ]
    _validate_current_generation(paths)
    certificate_exists = paths.server_certificate.is_file()
    key_exists = paths.server_private_key.is_file()
    if (
        certificate_exists
        and key_exists
        and _server_material_is_valid(paths, server_name, sans)
        and not _server_material_expires_within(paths, timedelta(days=7))
    ):
        return
    issued = service.certificate_authority.issue_server_certificate(server_name, sans)
    _publish_server_generation(
        paths,
        issued.certificate_pem,
        issued.private_key_pem,
    )


@contextmanager
def _initialization_lock(directory: Path) -> Iterator[None]:
    """Serialize first-time CA creation across local Form processes."""
    _ensure_private_directory(directory)
    lock_path = directory / ".initialize.lock"
    descriptor = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with _PROCESS_LOCK:
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            except ImportError:  # pragma: no cover - Form production image is Linux
                pass
            yield
    finally:
        os.close(descriptor)


def renew_agent_server_certificate(
    service: AgentIdentityService,
    paths: AgentRuntimePaths,
) -> None:
    """Check/renew the listener leaf while serializing all control replicas."""

    with _initialization_lock(paths.ca_private_key.parent):
        ensure_agent_server_certificate(service, paths)


def server_certificate_check_seconds() -> float:
    """Return a bounded cadence so a bad value cannot make renewal miss its window."""

    raw = os.getenv(
        "FORM_AGENT_TLS_RENEW_CHECK_SECONDS",
        str(DEFAULT_SERVER_CERTIFICATE_CHECK_SECONDS),
    )
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "invalid FORM_AGENT_TLS_RENEW_CHECK_SECONDS=%r; using %d",
            raw,
            DEFAULT_SERVER_CERTIFICATE_CHECK_SECONDS,
        )
        return float(DEFAULT_SERVER_CERTIFICATE_CHECK_SECONDS)
    if value <= 0:
        logger.warning(
            "non-positive FORM_AGENT_TLS_RENEW_CHECK_SECONDS=%r; using %d",
            raw,
            DEFAULT_SERVER_CERTIFICATE_CHECK_SECONDS,
        )
        return float(DEFAULT_SERVER_CERTIFICATE_CHECK_SECONDS)
    return min(value, float(MAX_SERVER_CERTIFICATE_CHECK_SECONDS))


async def maintain_agent_server_certificate(
    service: AgentIdentityService,
    paths: AgentRuntimePaths,
    *,
    check_seconds: float | None = None,
) -> None:
    """Periodically renew the dedicated listener leaf for a long-lived Form."""

    interval = check_seconds if check_seconds is not None else server_certificate_check_seconds()
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(renew_agent_server_certificate, service, paths)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - retain and retry the current valid generation
            logger.exception(
                "Agent listener certificate maintenance failed; keeping current generation"
            )


def load_or_create_agent_identity_service(
    data_dir: Path,
) -> tuple[AgentIdentityService, AgentRuntimePaths]:
    """Initialize/load the online CA and durable identity registry fail-closed."""
    paths = AgentRuntimePaths.from_env()
    _ensure_private_directory(paths.ca_private_key.parent)
    _ensure_private_directory(paths.tls_directory)
    with _initialization_lock(paths.ca_private_key.parent):
        certificate_exists = paths.ca_certificate.exists()
        key_exists = paths.ca_private_key.exists()
        if certificate_exists != key_exists:
            raise AgentCertificateAuthorityError(
                "Agent CA certificate/key are incomplete; refusing to rotate implicitly"
            )
        if certificate_exists:
            authority = AgentCertificateAuthority(
                paths.ca_certificate,
                paths.ca_private_key,
            )
        else:
            authority = AgentCertificateAuthority.initialize(
                paths.ca_certificate,
                paths.ca_private_key,
            )
    identity_data_dir = Path(os.getenv("FORM_AGENT_IDENTITY_DATA_DIR", str(data_dir)))
    repository = AgentIdentityRepository(identity_data_dir)
    service = AgentIdentityService(repository, authority)
    renew_agent_server_certificate(service, paths)
    return service, paths


__all__ = [
    "AgentRuntimePaths",
    "agent_identity_enabled",
    "ensure_agent_server_certificate",
    "load_or_create_agent_identity_service",
    "maintain_agent_server_certificate",
    "renew_agent_server_certificate",
    "server_certificate_check_seconds",
]
