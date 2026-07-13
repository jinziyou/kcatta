from __future__ import annotations

import asyncio
import stat
import threading
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi.testclient import TestClient

from kcatta_form import agent_runtime
from kcatta_form.agent_pki import AgentCertificateAuthorityError
from kcatta_form.analyzer_client import AnalyzerClient
from kcatta_form.api import app as form_app


def _configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORM_AGENT_PKI_DIR", str(tmp_path / "credentials" / "agent-pki"))
    monkeypatch.setenv("FORM_AGENT_TLS_DIR", str(tmp_path / "agent-tls"))
    monkeypatch.setenv("FORM_AGENT_IDENTITY_DATA_DIR", str(tmp_path / "agent-identities"))
    monkeypatch.setenv("FORM_AGENT_PUBLIC_URL", "https://agents.example.test:10443")


def _matching_pair(paths: agent_runtime.AgentRuntimePaths) -> bool:
    certificate = x509.load_pem_x509_certificate(paths.server_certificate.read_bytes())
    private_key = serialization.load_pem_private_key(
        paths.server_private_key.read_bytes(),
        password=None,
    )
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return certificate_public == key_public


def test_runtime_publishes_atomic_server_generation_with_private_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(tmp_path, monkeypatch)

    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    try:
        assert paths.server_current.is_symlink()
        assert paths.server_current.readlink().name.startswith("generation-")
        assert paths.server_certificate.is_file()
        assert paths.server_private_key.is_file()
        assert _matching_pair(paths)
        assert stat.S_IMODE(paths.server_private_key.stat().st_mode) == 0o600
        assert stat.S_IMODE(paths.ca_private_key.stat().st_mode) == 0o600
        assert paths.ca_private_key.parent != service.repository.db_path.parent
    finally:
        service.repository.close()


def test_expiring_server_leaf_rotates_by_one_atomic_current_switch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(tmp_path, monkeypatch)
    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    previous_target = paths.server_current.readlink()
    previous_fingerprint = x509.load_pem_x509_certificate(
        paths.server_certificate.read_bytes()
    ).fingerprint(hashes.SHA256())
    monkeypatch.setattr(agent_runtime, "_server_material_expires_within", lambda *_args: True)

    try:
        agent_runtime.ensure_agent_server_certificate(service, paths)
        current_fingerprint = x509.load_pem_x509_certificate(
            paths.server_certificate.read_bytes()
        ).fingerprint(hashes.SHA256())

        assert paths.server_current.readlink() != previous_target
        assert current_fingerprint != previous_fingerprint
        assert _matching_pair(paths)
        assert (paths.tls_directory / previous_target).is_dir()
    finally:
        service.repository.close()


def test_runtime_rejects_unsafe_current_symlink_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(tmp_path, monkeypatch)
    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    paths.server_current.unlink()
    paths.server_current.symlink_to("../credentials")

    try:
        with pytest.raises(AgentCertificateAuthorityError, match="unsafe target"):
            agent_runtime.ensure_agent_server_certificate(service, paths)
    finally:
        service.repository.close()


def test_runtime_rejects_agent_public_url_with_a_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(tmp_path, monkeypatch)
    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    monkeypatch.setenv("FORM_AGENT_PUBLIC_URL", "https://agents.example.test:10443/ingest")

    try:
        with pytest.raises(ValueError, match="pure origin"):
            agent_runtime.ensure_agent_server_certificate(service, paths)
    finally:
        service.repository.close()


def test_server_leaf_rotates_when_required_sans_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(tmp_path, monkeypatch)
    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    previous_target = paths.server_current.readlink()
    monkeypatch.setenv("FORM_AGENT_TLS_SANS", "alias.example.test,192.0.2.44")

    try:
        agent_runtime.ensure_agent_server_certificate(service, paths)
        certificate = x509.load_pem_x509_certificate(paths.server_certificate.read_bytes())
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value

        assert paths.server_current.readlink() != previous_target
        assert "alias.example.test" in names.get_values_for_type(x509.DNSName)
        assert "192.0.2.44" in {str(value) for value in names.get_values_for_type(x509.IPAddress)}
    finally:
        service.repository.close()


def test_server_certificate_check_interval_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORM_AGENT_TLS_RENEW_CHECK_SECONDS", "999999")
    assert (
        agent_runtime.server_certificate_check_seconds()
        == agent_runtime.MAX_SERVER_CERTIFICATE_CHECK_SECONDS
    )

    monkeypatch.setenv("FORM_AGENT_TLS_RENEW_CHECK_SECONDS", "invalid")
    assert (
        agent_runtime.server_certificate_check_seconds()
        == agent_runtime.DEFAULT_SERVER_CERTIFICATE_CHECK_SECONDS
    )


def test_certificate_maintenance_retries_after_a_failed_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []

    def renew(service: object, paths: object) -> None:
        calls.append((service, paths))
        if len(calls) == 1:
            raise OSError("temporary publication failure")

    monkeypatch.setattr(agent_runtime, "renew_agent_server_certificate", renew)

    async def scenario() -> None:
        task = asyncio.create_task(
            agent_runtime.maintain_agent_server_certificate(
                object(),  # type: ignore[arg-type]
                object(),  # type: ignore[arg-type]
                check_seconds=0.001,
            )
        )
        try:
            async with asyncio.timeout(1):
                while len(calls) < 2:
                    await asyncio.sleep(0.001)
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(scenario())
    assert len(calls) >= 2


def test_control_lifespan_owns_certificate_maintenance_task(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    started = threading.Event()
    stopped = threading.Event()

    async def maintenance(*_args: object, **_kwargs: object) -> None:
        started.set()
        try:
            await asyncio.Future()
        finally:
            stopped.set()

    monkeypatch.setattr(form_app, "maintain_agent_server_certificate", maintenance)
    analyzer = AnalyzerClient(
        "http://analyzer.internal:10068",
        "internal-test-token",
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=[])),
    )
    app = form_app.create_app(
        data_dir=tmp_path / "data",
        api_token="admin-test-token",
        agent_auth_mode="mtls",
        storage_backend="sqlite",
        analyzer_client=analyzer,
    )

    with TestClient(app):
        assert started.wait(timeout=1)
        assert app.state.agent_server_certificate_task is not None
        assert not app.state.agent_server_certificate_task.done()

    assert stopped.wait(timeout=1)
