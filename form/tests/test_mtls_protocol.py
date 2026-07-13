from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from kcatta_form.mtls_protocol import certificate_metadata, peer_certificate_from_scope


def _certificate_der() -> tuple[bytes, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(123456789)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER), certificate


def test_certificate_metadata_uses_der_sha256_and_normalized_serial() -> None:
    der, certificate = _certificate_der()

    metadata = certificate_metadata(der)

    assert metadata["serial"] == format(certificate.serial_number, "x")
    assert len(metadata["sha256"]) == 64
    assert metadata["subject"] == "CN=agent-test"


def test_peer_certificate_scope_parser_rejects_untrusted_shapes() -> None:
    assert peer_certificate_from_scope({}) is None
    assert peer_certificate_from_scope({"extensions": {"kcatta.mtls": "spoof"}}) is None
    assert peer_certificate_from_scope(
        {"extensions": {"kcatta.mtls": {"sha256": "abc", "serial": "DEF"}}}
    ) == {"sha256": "abc", "serial": "def", "subject": ""}
