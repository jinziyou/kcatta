"""Uvicorn HTTP protocol that exposes the verified TLS peer certificate to ASGI.

Uvicorn deliberately keeps transport details out of its normal HTTP scope.  The
Agent ingest listener needs the certificate that *this* TLS connection actually
presented, rather than a spoofable forwarding header, so its dedicated listener
uses this small h11 protocol subclass.  The SSL context is configured with
``CERT_REQUIRED`` by :func:`kcatta_form.cli.agent_api_main`; reaching the ASGI
application therefore already implies a valid chain to Form's Agent CA.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography import x509
from uvicorn.protocols.http.h11_impl import H11Protocol

MTLS_SCOPE_EXTENSION = "kcatta.mtls"


def certificate_metadata(der_certificate: bytes) -> dict[str, str]:
    """Return stable, non-secret identifiers for one DER certificate."""
    certificate = x509.load_der_x509_certificate(der_certificate)
    return {
        "sha256": hashlib.sha256(der_certificate).hexdigest(),
        "serial": format(certificate.serial_number, "x"),
        "subject": certificate.subject.rfc4514_string(),
    }


class MtlsH11Protocol(H11Protocol):
    """Attach verified peer-certificate metadata to each HTTP ASGI scope.

    ``H11Protocol.handle_events`` schedules the ASGI task but does not yield to
    it before returning, so extending the newly-created mutable scope directly
    afterwards is deterministic.  A focused regression test guards this narrow
    integration point against future Uvicorn upgrades.
    """

    _kcatta_peer: dict[str, str] | None

    def connection_made(self, transport: Any) -> None:
        super().connection_made(transport)
        self._kcatta_peer = None
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            return
        der_certificate = ssl_object.getpeercert(binary_form=True)
        if der_certificate:
            self._kcatta_peer = certificate_metadata(der_certificate)

    def handle_events(self) -> None:
        previous_scope = getattr(self, "scope", None)
        super().handle_events()
        scope = getattr(self, "scope", None)
        if scope is previous_scope or scope is None or self._kcatta_peer is None:
            return
        extensions = scope.setdefault("extensions", {})
        extensions[MTLS_SCOPE_EXTENSION] = dict(self._kcatta_peer)


def peer_certificate_from_scope(scope: dict[str, Any]) -> dict[str, str] | None:
    """Read metadata inserted by :class:`MtlsH11Protocol`, if present."""
    value = scope.get("extensions", {}).get(MTLS_SCOPE_EXTENSION)
    if not isinstance(value, dict):
        return None
    fingerprint = value.get("sha256")
    serial = value.get("serial")
    if not isinstance(fingerprint, str) or not isinstance(serial, str):
        return None
    return {
        "sha256": fingerprint.lower(),
        "serial": serial.lower(),
        "subject": str(value.get("subject", "")),
    }
