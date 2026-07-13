from __future__ import annotations

import ipaddress
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from kcatta_form.agent_identity_store import AgentIdentityRepository
from kcatta_form.agent_pki import (
    AgentCertificateAuthority,
    AgentCertificateAuthorityError,
    AgentIdentityService,
)
from kcatta_form.schemas.agent_identity import AgentCertificateState, AgentScope

NOW = datetime(2026, 7, 13, 8, 0, tzinfo=UTC)


def _service(
    tmp_path: Path,
) -> tuple[AgentIdentityService, AgentIdentityRepository, Path, Path]:
    data_dir = tmp_path / "data"
    credentials_dir = tmp_path / "credentials"
    ca_cert_path = credentials_dir / "agent-ca.pem"
    ca_key_path = credentials_dir / "agent-ca-key.pem"
    ca = AgentCertificateAuthority.initialize(
        ca_cert_path,
        ca_key_path,
        validity=timedelta(days=365),
        now=NOW,
    )
    repository = AgentIdentityRepository(data_dir)
    return AgentIdentityService(repository, ca), repository, ca_cert_path, ca_key_path


def _public_key_der(key) -> bytes:  # type: ignore[no-untyped-def]
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_issued_bundle_has_client_auth_spiffe_identity_and_no_persisted_leaf_key(
    tmp_path: Path,
) -> None:
    service, repository, ca_cert_path, ca_key_path = _service(tmp_path)
    result = service.stage_for_target(
        "target-1",
        "host-canonical-1",
        [AgentScope.GUARD_EVENT, AgentScope.ASSET_REPORT],
        agent_id="agent-server-owned-1",
        idempotency_key="scan-job-secret",
        validity=timedelta(hours=12),
        now=NOW,
    )

    assert result.created is True
    assert result.deployment_material_available is True
    assert result.bundle is not None
    bundle = result.bundle
    certificate = x509.load_pem_x509_certificate(bundle.certificate_pem.encode())
    ca_certificate = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    private_key = serialization.load_pem_private_key(
        bundle.private_key_pem.encode(),
        password=None,
    )

    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        "agent-server-owned-1"
    )
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [
        "spiffe://kcatta/agent/agent-server-owned-1"
    ]
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value == (
        x509.BasicConstraints(ca=False, path_length=None)
    )
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature is True
    assert usage.key_cert_sign is False
    extended_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(extended_usage) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert _public_key_der(private_key.public_key()) == _public_key_der(certificate.public_key())
    ca_certificate.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        ec.ECDSA(certificate.signature_hash_algorithm),
    )
    assert stat.S_IMODE(ca_key_path.stat().st_mode) == 0o600
    assert bundle.private_key_pem not in repr(bundle)

    data_dir = repository.db_path.parent
    for path in data_dir.rglob("*"):
        if path.is_file():
            contents = path.read_bytes()
            assert b"PRIVATE KEY" not in contents
            assert b"scan-job-secret" not in contents

    # Staged certificates cannot authenticate.  After activation, identity and
    # scopes come from the TLS fingerprint registry; spoofed claim keys are ignored.
    assert (
        service.verify_peer_certificate(
            {
                "sha256": result.certificate.cert_sha256,
                "serial": result.certificate.serial_number,
                "agent_id": "attacker-selected",
                "canonical_host_id": "attacker-host",
            },
            now=NOW,
        )
        is None
    )
    service.activate(result.identity.agent_id, 1, now=NOW)
    principal = service.verify_peer_certificate(
        {
            "sha256": result.certificate.cert_sha256,
            "serial": result.certificate.serial_number,
            "agent_id": "attacker-selected",
            "canonical_host_id": "attacker-host",
            "scopes": ["anything"],
        },
        now=NOW,
    )
    assert principal is not None
    assert principal.agent_id == "agent-server-owned-1"
    assert principal.target_id == "target-1"
    assert principal.canonical_host_id == "host-canonical-1"
    assert principal.scopes == [AgentScope.ASSET_REPORT, AgentScope.GUARD_EVENT]


def test_stage_for_target_replay_is_metadata_only_and_abort_preserves_old_active(
    tmp_path: Path,
) -> None:
    service, repository, _ca_cert_path, _ca_key_path = _service(tmp_path)
    first = service.stage_for_target(
        "target-1",
        "host-1",
        [AgentScope.TRACE_BATCH],
        idempotency_key="scan-job-1",
        now=NOW,
    )
    replay = service.stage_for_target(
        "target-1",
        "host-1",
        [AgentScope.TRACE_BATCH],
        idempotency_key="scan-job-1",
        now=NOW + timedelta(seconds=1),
    )
    assert first.created is True and first.bundle is not None
    assert replay.created is False and replay.bundle is None
    assert replay.certificate.cert_sha256 == first.certificate.cert_sha256
    assert replay.certificate.generation == first.certificate.generation == 1

    service.activate(first.identity.agent_id, 1, now=NOW + timedelta(minutes=1))
    active_replay = service.stage_for_target(
        "target-1",
        "host-1",
        [AgentScope.TRACE_BATCH],
        idempotency_key="scan-job-1",
        now=NOW + timedelta(minutes=2),
    )
    assert active_replay.created is False
    assert active_replay.bundle is None
    assert active_replay.certificate.state is AgentCertificateState.ACTIVE

    rotation = service.stage_for_target(
        "target-1",
        "host-1",
        [AgentScope.TRACE_BATCH],
        idempotency_key="scan-job-2",
        now=NOW + timedelta(minutes=3),
    )
    assert rotation.created is True and rotation.bundle is not None
    assert rotation.certificate.generation == 2
    service.abort(
        rotation.identity.agent_id,
        rotation.certificate.generation,
        now=NOW + timedelta(minutes=4),
    )
    # Deployment failure only revokes staged generation 2; generation 1 keeps serving.
    assert (
        repository.verify(
            cert_sha256=first.certificate.cert_sha256,
            now=NOW + timedelta(minutes=5),
        )
        is not None
    )
    assert (
        repository.verify(
            cert_sha256=rotation.certificate.cert_sha256,
            now=NOW + timedelta(minutes=5),
        )
        is None
    )

    retry_after_abort = service.stage_for_target(
        "target-1",
        "host-1",
        [AgentScope.TRACE_BATCH],
        idempotency_key="scan-job-2",
        now=NOW + timedelta(minutes=6),
    )
    assert retry_after_abort.created is True
    assert retry_after_abort.bundle is not None
    assert retry_after_abort.certificate.generation == 3
    assert retry_after_abort.certificate.cert_sha256 != rotation.certificate.cert_sha256
    assert (
        repository.verify(
            cert_sha256=first.certificate.cert_sha256,
            now=NOW + timedelta(minutes=7),
        )
        is not None
    )


def test_server_certificate_has_separate_server_auth_role_and_dns_ip_sans(
    tmp_path: Path,
) -> None:
    service, _repository, _ca_cert_path, _ca_key_path = _service(tmp_path)

    material = service.certificate_authority.issue_server_certificate(
        "form-agent.internal",
        ["localhost", "127.0.0.1", "form-agent.internal"],
        validity=timedelta(days=7),
        now=NOW,
    )
    certificate = x509.load_pem_x509_certificate(material.certificate_pem.encode())
    private_key = serialization.load_pem_private_key(
        material.private_key_pem.encode(),
        password=None,
    )
    extended_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(extended_usage) == [ExtendedKeyUsageOID.SERVER_AUTH]
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in extended_usage
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["form-agent.internal", "localhost"]
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("127.0.0.1")]
    assert _public_key_der(private_key.public_key()) == _public_key_der(certificate.public_key())
    assert material.private_key_pem not in repr(material)


def test_service_rejects_ca_private_key_inside_data_and_ca_symlink(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    repository = AgentIdentityRepository(data_dir)
    ca = AgentCertificateAuthority.initialize(
        data_dir / "ca.pem",
        data_dir / "ca-key.pem",
        now=NOW,
    )
    with pytest.raises(AgentCertificateAuthorityError, match="outside"):
        AgentIdentityService(repository, ca)

    linked_key = tmp_path / "linked-ca-key.pem"
    os.symlink(ca.private_key_path, linked_key)
    with pytest.raises(AgentCertificateAuthorityError, match="symlink"):
        AgentCertificateAuthority(ca.certificate_path, linked_key)
