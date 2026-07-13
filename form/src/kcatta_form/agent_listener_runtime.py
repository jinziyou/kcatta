"""Reload supervisor for Form's dedicated Agent mTLS listener."""

from __future__ import annotations

import hashlib
import logging
import ssl
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from queue import Empty, Queue
from types import FrameType

import uvicorn
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from .mtls_protocol import MtlsH11Protocol

logger = logging.getLogger("kcatta_form.agent_listener_runtime")

DEFAULT_TLS_RELOAD_POLL_SECONDS = 5.0
DEFAULT_GRACEFUL_SHUTDOWN_SECONDS = 30
MAX_TLS_FILE_BYTES = 1024 * 1024


class ListenerTlsMaterialError(RuntimeError):
    """The published listener TLS snapshot is unsafe, incomplete, or invalid."""


@dataclass(frozen=True)
class ListenerTlsMaterial:
    """One validated, immutable TLS generation used to build an SSLContext."""

    certificate: Path
    private_key: Path
    client_ca: Path
    stamp: str


def _resolve_snapshot_paths(
    certificate: Path,
    private_key: Path,
    client_ca: Path,
) -> tuple[Path, Path, Path]:
    """Resolve the shared cert/key generation once, never one file at a time."""

    try:
        if certificate.parent == private_key.parent:
            server_generation = certificate.parent.resolve(strict=True)
            certificate_path = server_generation / certificate.name
            private_key_path = server_generation / private_key.name
        else:
            certificate_path = certificate.resolve(strict=True)
            private_key_path = private_key.resolve(strict=True)
        return (
            certificate_path,
            private_key_path,
            client_ca.resolve(strict=True),
        )
    except OSError as exc:
        raise ListenerTlsMaterialError("cannot resolve listener TLS generation") from exc


def _read_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ListenerTlsMaterialError(f"TLS material is not a regular file: {path}")
        if metadata.st_size > MAX_TLS_FILE_BYTES:
            raise ListenerTlsMaterialError(f"TLS material exceeds size limit: {path}")
        content = path.read_bytes()
    except ListenerTlsMaterialError:
        raise
    except OSError as exc:
        raise ListenerTlsMaterialError(f"cannot read TLS material: {path}") from exc
    return content


def _validate_tls_snapshot(
    certificate_pem: bytes,
    private_key_pem: bytes,
    client_ca_pem: bytes,
) -> None:
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        authority = x509.load_pem_x509_certificate(client_ca_pem)
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        certificate_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if certificate_public != key_public:
            raise ListenerTlsMaterialError("listener certificate/private key do not match")
        if certificate.issuer != authority.subject:
            raise ListenerTlsMaterialError("listener certificate was not issued by the client CA")
        authority_public_key = authority.public_key()
        if not isinstance(authority_public_key, ec.EllipticCurvePublicKey):
            raise ListenerTlsMaterialError("listener CA must use an EC signing key")
        authority_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
        now = datetime.now(UTC)
        if not (certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc):
            raise ListenerTlsMaterialError("listener certificate is not currently valid")
        if not (authority.not_valid_before_utc <= now < authority.not_valid_after_utc):
            raise ListenerTlsMaterialError("listener client CA is not currently valid")
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in usage:
            raise ListenerTlsMaterialError("listener certificate lacks serverAuth usage")
        constraints = authority.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca:
            raise ListenerTlsMaterialError("listener client CA certificate is not a CA")
    except ListenerTlsMaterialError:
        raise
    except (
        InvalidSignature,
        UnsupportedAlgorithm,
        TypeError,
        ValueError,
        x509.ExtensionNotFound,
    ) as exc:
        raise ListenerTlsMaterialError("invalid listener TLS certificate material") from exc


def load_listener_tls_material(
    certificate: Path,
    private_key: Path,
    client_ca: Path,
) -> ListenerTlsMaterial:
    """Read and validate one coherent snapshot across an atomic generation switch."""

    first_paths = _resolve_snapshot_paths(certificate, private_key, client_ca)
    first_content = tuple(_read_regular_file(path) for path in first_paths)
    second_paths = _resolve_snapshot_paths(certificate, private_key, client_ca)
    second_content = tuple(_read_regular_file(path) for path in second_paths)
    if first_paths != second_paths or first_content != second_content:
        raise ListenerTlsMaterialError("listener TLS generation changed while it was being read")

    certificate_path, key_path, ca_path = first_paths
    certificate_pem, key_pem, ca_pem = first_content
    _validate_tls_snapshot(certificate_pem, key_pem, ca_pem)
    digest = hashlib.sha256()
    for content in (certificate_pem, key_pem, ca_pem):
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return ListenerTlsMaterial(
        certificate=certificate_path,
        private_key=key_path,
        client_ca=ca_path,
        stamp=digest.hexdigest(),
    )


class _ReloadableAgentServer(uvicorn.Server):
    """Uvicorn server that distinguishes operator shutdown from TLS recycle."""

    external_exit_requested = False

    def handle_exit(self, sig: int, frame: FrameType | None) -> None:
        self.external_exit_requested = True
        super().handle_exit(sig, frame)


def _watch_tls_material(
    server: uvicorn.Server,
    current: ListenerTlsMaterial,
    certificate: Path,
    private_key: Path,
    client_ca: Path,
    stop: threading.Event,
    reload_requested: threading.Event,
    poll_seconds: float,
    shutdown_requested: threading.Event | None,
    validated_candidates: Queue[ListenerTlsMaterial],
) -> None:
    while not stop.wait(poll_seconds):
        if shutdown_requested is not None and shutdown_requested.is_set():
            server.should_exit = True
            return
        try:
            candidate = load_listener_tls_material(certificate, private_key, client_ca)
        except ListenerTlsMaterialError as exc:
            # A partial/bad publication must never take down the known-good SSLContext.
            logger.warning("ignoring invalid Agent listener TLS publication: %s", exc)
            continue
        except Exception:  # noqa: BLE001 - availability boundary retains the LKG
            # Treat unexpected parser/library failures like a bad candidate.
            # The currently running SSLContext is already validated; killing its
            # watcher would silently disable future renewal until a process
            # restart, while continuing with the LKG is fail-closed and visible.
            logger.exception("ignoring unexpected Agent listener TLS candidate failure")
            continue
        if candidate.stamp == current.stamp:
            continue
        logger.info("new Agent listener TLS generation detected; starting graceful recycle")
        validated_candidates.put_nowait(candidate)
        reload_requested.set()
        server.should_exit = True
        return


def run_reloadable_agent_listener(
    *,
    host: str,
    port: int,
    certificate: Path,
    private_key: Path,
    client_ca: Path,
    poll_seconds: float = DEFAULT_TLS_RELOAD_POLL_SECONDS,
    graceful_shutdown_seconds: int = DEFAULT_GRACEFUL_SHUTDOWN_SECONDS,
    server_factory: Callable[[uvicorn.Config], uvicorn.Server] = _ReloadableAgentServer,
    shutdown_requested: threading.Event | None = None,
) -> None:
    """Serve mTLS forever, gracefully rebuilding SSLContext when material changes."""

    if poll_seconds <= 0:
        raise ValueError("Agent listener TLS poll interval must be positive")
    if graceful_shutdown_seconds <= 0:
        raise ValueError("Agent listener graceful shutdown timeout must be positive")

    next_material: ListenerTlsMaterial | None = None
    while True:
        material = next_material or load_listener_tls_material(certificate, private_key, client_ca)
        next_material = None
        config = uvicorn.Config(
            "kcatta_form.api.agent_app:create_agent_app",
            host=host,
            port=port,
            factory=True,
            http=MtlsH11Protocol,
            ws="none",
            ssl_certfile=str(material.certificate),
            ssl_keyfile=str(material.private_key),
            ssl_ca_certs=str(material.client_ca),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            proxy_headers=False,
            timeout_graceful_shutdown=graceful_shutdown_seconds,
        )
        server = server_factory(config)
        stop = threading.Event()
        reload_requested = threading.Event()
        validated_candidates: Queue[ListenerTlsMaterial] = Queue(maxsize=1)
        watcher = threading.Thread(
            target=_watch_tls_material,
            args=(
                server,
                material,
                certificate,
                private_key,
                client_ca,
                stop,
                reload_requested,
                poll_seconds,
                shutdown_requested,
                validated_candidates,
            ),
            name="form-agent-tls-generation-watcher",
            daemon=True,
        )
        watcher.start()
        try:
            server.run()
        finally:
            stop.set()
            watcher.join(timeout=max(1.0, poll_seconds + 1.0))
        if getattr(server, "external_exit_requested", False) or not reload_requested.is_set():
            return
        # Never follow ``current`` again after taking down the known-good
        # server. The watcher already validated and pinned a concrete
        # generation; if its handoff is unexpectedly absent, recycle the
        # current LKG instead of risking a partial publication.
        try:
            next_material = validated_candidates.get_nowait()
        except Empty:  # pragma: no cover - defensive against future watcher changes
            logger.error("TLS recycle requested without a validated candidate; reusing LKG")
            next_material = material


__all__ = [
    "ListenerTlsMaterial",
    "ListenerTlsMaterialError",
    "load_listener_tls_material",
    "run_reloadable_agent_listener",
]
