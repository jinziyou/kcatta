"""Form-owned PKI and one-time client-certificate deployment bundles.

The CA key path is injected explicitly and must live outside Form's data
directory.  Leaf keys are generated in memory, returned once to the deployment
layer, and never persisted by either this service or the identity repository.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import stat
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .agent_identity_store import AgentIdentityRepository
from .schemas.agent_identity import (
    AgentCertificate,
    AgentCertificateBundle,
    AgentIdentity,
    AgentIdentityState,
    AgentScope,
    VerifiedAgentIdentity,
)

DEFAULT_AGENT_CERT_VALIDITY = timedelta(days=30)
MAX_AGENT_CERT_VALIDITY = timedelta(days=90)
DEFAULT_SERVER_CERT_VALIDITY = timedelta(days=30)
MAX_SERVER_CERT_VALIDITY = timedelta(days=90)
DEFAULT_CA_VALIDITY = timedelta(days=3650)
CERTIFICATE_CLOCK_SKEW = timedelta(minutes=5)

_AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")


class AgentPkiError(RuntimeError):
    """Base error for CA loading and certificate issuance."""


class AgentCertificateAuthorityError(AgentPkiError):
    """The configured CA material is missing, invalid, or unsafe."""


@dataclass(frozen=True)
class IssuedAgentCertificate:
    """Ephemeral leaf material before its public metadata is staged."""

    serial_number: str
    cert_sha256: str
    spki_sha256: str
    not_before: datetime
    not_after: datetime
    certificate_pem: str
    private_key_pem: str = field(repr=False)
    ca_certificate_pem: str


@dataclass(frozen=True)
class IssuedServerCertificate:
    """Ephemeral ``serverAuth`` material for Form's dedicated mTLS listener."""

    serial_number: str
    cert_sha256: str
    spki_sha256: str
    not_before: datetime
    not_after: datetime
    certificate_pem: str
    private_key_pem: str = field(repr=False)
    ca_certificate_pem: str


@dataclass(frozen=True)
class StagedAgentCertificateResult:
    """Result of an idempotent target staging request.

    ``bundle`` exists only for the call that created the staged generation.
    A retry with the same target/key gets the same generation's public metadata with
    ``created=False`` and ``bundle=None`` because Form never persists leaf
    private keys.  If deployment failed, the caller must explicitly ``abort``
    that staged generation before requesting a new one; abort never affects the
    previous active certificate.  Activation preserves this idempotency
    reservation; abort releases it so a deployment retry can create a new
    generation with the same scan-job key.
    """

    identity: AgentIdentity
    certificate: AgentCertificate
    created: bool
    bundle: AgentCertificateBundle | None = field(default=None, repr=False)

    @property
    def deployment_material_available(self) -> bool:
        return self.bundle is not None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _regular_file_bytes(path: Path, description: str, *, max_bytes: int) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise AgentCertificateAuthorityError(f"{description} does not exist: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise AgentCertificateAuthorityError(f"{description} must not be a symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise AgentCertificateAuthorityError(f"{description} is not a regular file: {path}")
    if metadata.st_size > max_bytes:
        raise AgentCertificateAuthorityError(f"{description} is unexpectedly large: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AgentCertificateAuthorityError(f"cannot read {description}: {path}") from exc


def _temporary_file(path: Path, data: bytes, mode: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary_path
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
        raise


def _install_file(path: Path, data: bytes, mode: int) -> None:
    temporary_path = _temporary_file(path, data, mode)
    try:
        try:
            # A hard-link publication is atomic and fails if another Form
            # process initialized this path first.  Unlike ``replace``, it can
            # never overwrite CA material after the preflight existence check.
            os.link(temporary_path, path)
        except FileExistsError as exc:
            raise AgentCertificateAuthorityError(
                f"refusing to overwrite existing CA material: {path}"
            ) from exc
        os.chmod(path, mode)
        try:
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary_path.unlink(missing_ok=True)


def _same_public_key(private_key: Any, certificate: x509.Certificate) -> bool:
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_public == certificate_public


def _server_general_name(value: str) -> x509.GeneralName:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 253
        or any(character.isspace() for character in normalized)
    ):
        raise ValueError("server SAN must be a non-empty DNS name or IP address")
    try:
        return x509.IPAddress(ipaddress.ip_address(normalized))
    except ValueError:
        pass
    if "/" in normalized or "\x00" in normalized:
        raise ValueError("server DNS SAN contains an invalid character")
    wildcard = normalized.startswith("*.")
    idna_input = normalized[2:] if wildcard else normalized
    try:
        ascii_name = idna_input.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid server DNS SAN: {normalized}") from exc
    if not ascii_name or any(not label for label in ascii_name.split(".")):
        raise ValueError(f"invalid server DNS SAN: {normalized}")
    return x509.DNSName(f"*.{ascii_name}" if wildcard else ascii_name)


class AgentCertificateAuthority:
    """Loaded online CA with explicitly injected certificate and key paths."""

    def __init__(
        self,
        certificate_path: Path,
        private_key_path: Path,
        *,
        private_key_password: bytes | None = None,
    ) -> None:
        self.certificate_path = Path(certificate_path)
        self.private_key_path = Path(private_key_path)
        if self.certificate_path.absolute() == self.private_key_path.absolute():
            raise AgentCertificateAuthorityError("CA certificate and private key paths must differ")

        certificate_bytes = _regular_file_bytes(
            self.certificate_path,
            "CA certificate",
            max_bytes=1024 * 1024,
        )
        private_key_bytes = _regular_file_bytes(
            self.private_key_path,
            "CA private key",
            max_bytes=1024 * 1024,
        )
        try:
            certificate = x509.load_pem_x509_certificate(certificate_bytes)
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=private_key_password,
            )
        except (TypeError, ValueError) as exc:
            raise AgentCertificateAuthorityError("cannot parse configured CA material") from exc
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
            private_key.curve,
            ec.SECP256R1,
        ):
            raise AgentCertificateAuthorityError("Agent CA must use a P-256 EC private key")
        if not _same_public_key(private_key, certificate):
            raise AgentCertificateAuthorityError("CA certificate does not match its private key")
        try:
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound as exc:
            raise AgentCertificateAuthorityError("CA certificate lacks BasicConstraints") from exc
        if not constraints.ca:
            raise AgentCertificateAuthorityError("configured certificate is not a CA")
        try:
            usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound as exc:
            raise AgentCertificateAuthorityError("CA certificate lacks KeyUsage") from exc
        if not usage.key_cert_sign:
            raise AgentCertificateAuthorityError("CA certificate cannot sign certificates")

        self._certificate = certificate
        self._private_key = private_key
        self._certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    @classmethod
    def initialize(
        cls,
        certificate_path: Path,
        private_key_path: Path,
        *,
        common_name: str = "kcatta Agent CA",
        validity: timedelta = DEFAULT_CA_VALIDITY,
        now: datetime | None = None,
    ) -> AgentCertificateAuthority:
        """Create new CA material without ever overwriting an existing path."""

        certificate_path = Path(certificate_path)
        private_key_path = Path(private_key_path)
        if certificate_path.absolute() == private_key_path.absolute():
            raise AgentCertificateAuthorityError("CA certificate and private key paths must differ")
        if certificate_path.exists() or private_key_path.exists():
            raise AgentCertificateAuthorityError("refusing to overwrite existing CA material")
        name = common_name.strip()
        if not name or len(name) > 256:
            raise ValueError("common_name must contain between 1 and 256 characters")
        if validity <= timedelta(0):
            raise ValueError("CA validity must be positive")

        timestamp = _utc(now or datetime.now(UTC))
        private_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(timestamp - CERTIFICATE_CLOCK_SKEW)
            .not_valid_after(timestamp + validity)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key=private_key, algorithm=hashes.SHA256())
        )
        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

        # The key is installed first with 0600.  A process crash may leave one
        # half, but never causes a silent overwrite or exposes an incomplete CA
        # as usable; the next load fails closed until an operator repairs it.
        try:
            _install_file(private_key_path, private_key_pem, 0o600)
            _install_file(certificate_path, certificate_pem, 0o644)
        except Exception:
            # Do not delete a successfully installed private key: another actor
            # could have observed it, so automatically replacing it would risk
            # split CA state.  Initialization remains fail-closed.
            raise
        return cls(certificate_path, private_key_path)

    @property
    def certificate_pem(self) -> str:
        """Public CA certificate suitable for the agent trust bundle."""

        return self._certificate_pem

    def issue_agent_certificate(
        self,
        agent_id: str,
        *,
        validity: timedelta = DEFAULT_AGENT_CERT_VALIDITY,
        now: datetime | None = None,
    ) -> IssuedAgentCertificate:
        """Issue a short-lived ``clientAuth`` leaf for a server-owned agent id."""

        normalized_agent_id = agent_id.strip()
        if not _AGENT_ID_PATTERN.fullmatch(normalized_agent_id):
            raise ValueError("agent_id must be a URI-safe identifier of at most 128 characters")
        if validity <= timedelta(0) or validity > MAX_AGENT_CERT_VALIDITY:
            raise ValueError(
                "certificate validity must be positive and no greater than "
                f"{MAX_AGENT_CERT_VALIDITY.days} days"
            )
        timestamp = _utc(now or datetime.now(UTC))
        ca_not_before = self._certificate.not_valid_before_utc
        ca_not_after = self._certificate.not_valid_after_utc
        if timestamp < ca_not_before:
            raise AgentCertificateAuthorityError("CA certificate is not valid yet")
        if timestamp >= ca_not_after:
            raise AgentCertificateAuthorityError("CA certificate has expired")
        not_before = max(timestamp - CERTIFICATE_CLOCK_SKEW, ca_not_before)
        not_after = min(timestamp + validity, ca_not_after)
        if not_after <= timestamp:
            raise AgentCertificateAuthorityError("CA expires too soon to issue a leaf")

        private_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, normalized_agent_id)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(f"spiffe://kcatta/agent/{normalized_agent_id}")]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._certificate.public_key()),
                critical=False,
            )
            .sign(private_key=self._private_key, algorithm=hashes.SHA256())
        )
        certificate_der = certificate.public_bytes(serialization.Encoding.DER)
        public_key_der = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return IssuedAgentCertificate(
            serial_number=format(certificate.serial_number, "x"),
            cert_sha256=hashlib.sha256(certificate_der).hexdigest(),
            spki_sha256=hashlib.sha256(public_key_der).hexdigest(),
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            private_key_pem=private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            ca_certificate_pem=self._certificate_pem,
        )

    def issue_server_certificate(
        self,
        server_name: str,
        sans: Iterable[str] = (),
        *,
        validity: timedelta = DEFAULT_SERVER_CERT_VALIDITY,
        now: datetime | None = None,
    ) -> IssuedServerCertificate:
        """Issue ephemeral ``serverAuth`` material for the Agent mTLS listener.

        This is intentionally a separate builder from agent ``clientAuth``
        issuance, so the two roles can never be accidentally combined.  The
        returned leaf key may be written by the caller to a dedicated TLS
        secret volume; this CA service itself performs no leaf-key I/O.
        """

        normalized_server_name = server_name.strip()
        if not normalized_server_name or len(normalized_server_name) > 253:
            raise ValueError("server_name must contain between 1 and 253 characters")
        if validity <= timedelta(0) or validity > MAX_SERVER_CERT_VALIDITY:
            raise ValueError(
                "server certificate validity must be positive and no greater than "
                f"{MAX_SERVER_CERT_VALIDITY.days} days"
            )
        timestamp = _utc(now or datetime.now(UTC))
        ca_not_before = self._certificate.not_valid_before_utc
        ca_not_after = self._certificate.not_valid_after_utc
        if timestamp < ca_not_before:
            raise AgentCertificateAuthorityError("CA certificate is not valid yet")
        if timestamp >= ca_not_after:
            raise AgentCertificateAuthorityError("CA certificate has expired")
        not_before = max(timestamp - CERTIFICATE_CLOCK_SKEW, ca_not_before)
        not_after = min(timestamp + validity, ca_not_after)
        if not_after <= timestamp:
            raise AgentCertificateAuthorityError("CA expires too soon to issue a server leaf")

        general_names = [_server_general_name(normalized_server_name)]
        general_names.extend(_server_general_name(value) for value in sans)
        unique_names: list[x509.GeneralName] = []
        seen: set[tuple[type[x509.GeneralName], object]] = set()
        for name in general_names:
            key = (type(name), name.value)
            if key not in seen:
                seen.add(key)
                unique_names.append(name)

        private_key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, normalized_server_name)])
            )
            .issuer_name(self._certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName(unique_names), critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._certificate.public_key()),
                critical=False,
            )
            .sign(private_key=self._private_key, algorithm=hashes.SHA256())
        )
        certificate_der = certificate.public_bytes(serialization.Encoding.DER)
        public_key_der = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return IssuedServerCertificate(
            serial_number=format(certificate.serial_number, "x"),
            cert_sha256=hashlib.sha256(certificate_der).hexdigest(),
            spki_sha256=hashlib.sha256(public_key_der).hexdigest(),
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            private_key_pem=private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            ca_certificate_pem=self._certificate_pem,
        )


def _path_is_within(path: Path, directory: Path) -> bool:
    resolved_path = path.resolve(strict=False)
    resolved_directory = directory.resolve(strict=False)
    return resolved_path == resolved_directory or resolved_directory in resolved_path.parents


class AgentIdentityService:
    """Orchestrate stable identities, staged generations, and one-time bundles."""

    def __init__(
        self,
        repository: AgentIdentityRepository,
        certificate_authority: AgentCertificateAuthority,
    ) -> None:
        if _path_is_within(
            certificate_authority.private_key_path,
            repository.db_path.parent,
        ):
            raise AgentCertificateAuthorityError(
                "CA private key must live outside the Form data directory"
            )
        self.repository = repository
        self.certificate_authority = certificate_authority

    def ensure_identity(
        self,
        target_id: str,
        canonical_host_id: str,
        scopes: Iterable[AgentScope | str],
        *,
        agent_id: str | None = None,
        now: datetime | None = None,
    ) -> AgentIdentity:
        identity, _created = self.repository.get_or_create(
            target_id,
            canonical_host_id,
            scopes,
            agent_id=agent_id,
            now=now,
        )
        return identity

    def issue_staged(
        self,
        agent_id: str,
        *,
        validity: timedelta = DEFAULT_AGENT_CERT_VALIDITY,
        now: datetime | None = None,
    ) -> AgentCertificateBundle:
        """Generate a leaf and atomically stage its public metadata.

        The identity comes only from the repository.  There is intentionally no
        CSR, claimed host id, scope list, or client-selected subject parameter.
        """

        identity = self.repository.get(agent_id)
        if identity.state is not AgentIdentityState.ACTIVE:
            raise AgentPkiError("cannot issue a certificate for a revoked identity")
        generation = identity.generation + 1
        material = self.certificate_authority.issue_agent_certificate(
            identity.agent_id,
            validity=validity,
            now=now,
        )
        staged_identity, created = self.repository.stage_certificate(
            identity.agent_id,
            generation=generation,
            serial_number=material.serial_number,
            cert_sha256=material.cert_sha256,
            spki_sha256=material.spki_sha256,
            certificate_pem=material.certificate_pem,
            not_before=material.not_before,
            not_after=material.not_after,
            now=now,
        )
        if not created:  # No key means this is not an idempotent replay.
            raise AgentPkiError("unexpected non-creating certificate stage")
        certificate = next(
            item for item in staged_identity.certificates if item.generation == generation
        )
        return AgentCertificateBundle(
            identity=staged_identity,
            certificate=certificate,
            certificate_pem=material.certificate_pem,
            private_key_pem=material.private_key_pem,
            ca_certificate_pem=material.ca_certificate_pem,
        )

    def stage_for_target(
        self,
        target_id: str,
        canonical_host_id: str,
        scopes: Iterable[AgentScope | str],
        *,
        idempotency_key: str | None = None,
        agent_id: str | None = None,
        validity: timedelta = DEFAULT_AGENT_CERT_VALIDITY,
        now: datetime | None = None,
    ) -> StagedAgentCertificateResult:
        """Stage one target generation with optional scan-job idempotency.

        A same-key replay while the generation has not been aborted returns
        only its durable certificate metadata (even if it is already active or
        retired).  After an explicit ``abort``, the same key may create the next
        generation and receive fresh one-time material.
        """

        identity = self.ensure_identity(
            target_id,
            canonical_host_id,
            scopes,
            agent_id=agent_id,
            now=now,
        )
        if idempotency_key is not None:
            staged = self.repository.get_by_idempotency_key(
                identity.agent_id,
                idempotency_key,
            )
            if staged is not None:
                # Refresh so the returned head/certificate list is from the
                # same durable state as the metadata lookup.
                return StagedAgentCertificateResult(
                    identity=self.repository.get(identity.agent_id),
                    certificate=staged,
                    created=False,
                )

        generation = identity.generation + 1
        material = self.certificate_authority.issue_agent_certificate(
            identity.agent_id,
            validity=validity,
            now=now,
        )
        staged_identity, created = self.repository.stage_certificate(
            identity.agent_id,
            generation=generation,
            serial_number=material.serial_number,
            cert_sha256=material.cert_sha256,
            spki_sha256=material.spki_sha256,
            certificate_pem=material.certificate_pem,
            not_before=material.not_before,
            not_after=material.not_after,
            idempotency_key=idempotency_key,
            now=now,
        )
        if created:
            certificate = next(
                item for item in staged_identity.certificates if item.generation == generation
            )
            bundle = AgentCertificateBundle(
                identity=staged_identity,
                certificate=certificate,
                certificate_pem=material.certificate_pem,
                private_key_pem=material.private_key_pem,
                ca_certificate_pem=material.ca_certificate_pem,
            )
            return StagedAgentCertificateResult(
                identity=staged_identity,
                certificate=certificate,
                created=True,
                bundle=bundle,
            )

        # Another process won the same-key race.  Its public metadata is the
        # idempotent result; this process's unmatched in-memory key is discarded.
        if idempotency_key is None:
            raise AgentPkiError("non-idempotent stage unexpectedly replayed")
        replayed = self.repository.get_by_idempotency_key(
            identity.agent_id,
            idempotency_key,
        )
        if replayed is None:
            raise AgentPkiError("idempotent stage disappeared during replay")
        return StagedAgentCertificateResult(
            identity=staged_identity,
            certificate=replayed,
            created=False,
        )

    def provision(
        self,
        target_id: str,
        canonical_host_id: str,
        scopes: Iterable[AgentScope | str],
        *,
        agent_id: str | None = None,
        validity: timedelta = DEFAULT_AGENT_CERT_VALIDITY,
        now: datetime | None = None,
    ) -> AgentCertificateBundle:
        """Ensure a stable binding and return a one-time staged SFTP bundle."""

        identity = self.ensure_identity(
            target_id,
            canonical_host_id,
            scopes,
            agent_id=agent_id,
            now=now,
        )
        return self.issue_staged(identity.agent_id, validity=validity, now=now)

    def activate(
        self,
        agent_id: str,
        generation: int,
        *,
        overlap: timedelta | None = None,
        now: datetime | None = None,
    ) -> AgentIdentity:
        options: dict[str, Any] = {"now": now}
        if overlap is not None:
            options["overlap"] = overlap
        return self.repository.activate(agent_id, generation, **options)

    def abort(
        self,
        agent_id: str,
        generation: int,
        *,
        now: datetime | None = None,
    ) -> AgentIdentity:
        return self.repository.abort(agent_id, generation, now=now)

    def revoke(
        self,
        agent_id: str,
        *,
        generation: int | None = None,
        now: datetime | None = None,
    ) -> AgentIdentity:
        return self.repository.revoke(agent_id, generation=generation, now=now)

    def revoke_certificates(
        self,
        agent_id: str,
        *,
        now: datetime | None = None,
    ) -> AgentIdentity:
        """Invalidate all deployed keys without decommissioning the target identity."""

        return self.repository.revoke_certificates(agent_id, now=now)

    def verify_peer_certificate(
        self,
        peer_certificate: Mapping[str, object],
        *,
        now: datetime | None = None,
    ) -> VerifiedAgentIdentity | None:
        """Resolve transport-attested metadata, ignoring every identity claim."""

        cert_sha256 = peer_certificate.get("sha256")
        serial = peer_certificate.get("serial")
        if cert_sha256 is not None and not isinstance(cert_sha256, str):
            return None
        if serial is not None and not isinstance(serial, str):
            return None
        if cert_sha256 is None and serial is None:
            return None
        try:
            return self.repository.verify(
                cert_sha256=cert_sha256,
                serial_number=serial,
                now=now,
            )
        except ValueError:
            return None


__all__ = [
    "AgentCertificateAuthority",
    "AgentCertificateAuthorityError",
    "AgentIdentityService",
    "AgentPkiError",
    "CERTIFICATE_CLOCK_SKEW",
    "DEFAULT_AGENT_CERT_VALIDITY",
    "DEFAULT_CA_VALIDITY",
    "DEFAULT_SERVER_CERT_VALIDITY",
    "IssuedAgentCertificate",
    "IssuedServerCertificate",
    "MAX_AGENT_CERT_VALIDITY",
    "MAX_SERVER_CERT_VALIDITY",
    "StagedAgentCertificateResult",
]
