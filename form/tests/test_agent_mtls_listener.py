"""Real-socket integration tests for Form's dedicated Agent mTLS listener."""

from __future__ import annotations

import json
import ssl
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
import uvicorn

from kcatta_form.agent_identity_store import AgentIdentityRepository
from kcatta_form.agent_pki import AgentCertificateAuthority, AgentIdentityService
from kcatta_form.analyzer_client import AnalyzerClient
from kcatta_form.api.agent_app import create_agent_app
from kcatta_form.mtls_protocol import MtlsH11Protocol
from kcatta_form.schemas.agent_identity import AgentScope


@dataclass
class _RunningAgentListener:
    base_url: str
    ca_certificate: Path
    client_certificate: Path
    client_private_key: Path
    agent_id: str
    target_id: str
    canonical_host_id: str
    generation: int
    repository: AgentIdentityRepository
    upstream_requests: list[httpx.Request]

    def client(self) -> httpx.Client:
        context = ssl.create_default_context(cafile=str(self.ca_certificate))
        context.load_cert_chain(
            certfile=str(self.client_certificate),
            keyfile=str(self.client_private_key),
        )
        return httpx.Client(
            base_url=self.base_url,
            verify=context,
            timeout=3.0,
            trust_env=False,
        )

    def client_without_certificate(self) -> httpx.Client:
        context = ssl.create_default_context(cafile=str(self.ca_certificate))
        return httpx.Client(
            base_url=self.base_url,
            verify=context,
            timeout=3.0,
            trust_env=False,
        )


def _asset_report(report_id: str) -> dict[str, object]:
    return {
        "report_id": report_id,
        "collected_at": "2026-07-13T00:00:00Z",
        "scanner_version": "mtls-test",
        "host": {
            "host_id": "untrusted-payload-host",
            "hostname": "endpoint.example.test",
            "os": "Linux",
        },
        "assets": [],
        "vulnerabilities": [
            {
                "vuln_id": "finding-1",
                "source": "posture",
                "severity": "high",
                "affected_asset_id": "untrusted-payload-host",
            }
        ],
    }


def _trace_batch() -> dict[str, object]:
    return {
        "batch_id": "trace-mtls-1",
        "collected_at": "2026-07-13T00:00:00Z",
        "collector_id": "collector-1",
        "collector_version": "mtls-test",
        "events": [],
        "file_events": [],
        "process_events": [],
    }


@pytest.fixture
def agent_listener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_RunningAgentListener]:
    identity_dir = tmp_path / "identities"
    pki_dir = tmp_path / "pki"
    tls_dir = tmp_path / "listener-tls"
    client_dir = tmp_path / "client"
    pki_dir.mkdir()
    tls_dir.mkdir()
    client_dir.mkdir()

    ca_certificate = pki_dir / "ca-cert.pem"
    ca_private_key = pki_dir / "ca-key.pem"
    authority = AgentCertificateAuthority.initialize(ca_certificate, ca_private_key)
    repository = AgentIdentityRepository(identity_dir)
    identity_service = AgentIdentityService(repository, authority)
    bundle = identity_service.provision(
        "target-mtls-1",
        "canonical-host-mtls-1",
        [AgentScope.ASSET_REPORT],
        agent_id="agent-mtls-1",
    )
    identity_service.activate(bundle.identity.agent_id, bundle.certificate.generation)

    client_certificate = client_dir / "agent-cert.pem"
    client_private_key = client_dir / "agent-key.pem"
    client_certificate.write_text(bundle.certificate_pem, encoding="ascii")
    client_private_key.write_text(bundle.private_key_pem, encoding="ascii")

    server_material = authority.issue_server_certificate(
        "localhost",
        sans=["127.0.0.1"],
    )
    server_certificate = tls_dir / "server-cert.pem"
    server_private_key = tls_dir / "server-key.pem"
    server_certificate.write_text(server_material.certificate_pem, encoding="ascii")
    server_private_key.write_text(server_material.private_key_pem, encoding="ascii")

    upstream_requests: list[httpx.Request] = []

    def analyzer_handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(202, json={"accepted": True})

    analyzer = AnalyzerClient(
        "http://analyzer.internal:10068",
        "internal-test-token",
        transport=httpx.MockTransport(analyzer_handler),
    )
    monkeypatch.setenv("FORM_AGENT_IDENTITY_DATA_DIR", str(identity_dir))
    app = create_agent_app(data_dir=identity_dir, analyzer_client=analyzer)

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        loop="asyncio",
        http=MtlsH11Protocol,
        ws="none",
        lifespan="on",
        log_config=None,
        access_log=False,
        proxy_headers=False,
        ssl_certfile=str(server_certificate),
        ssl_keyfile=str(server_private_key),
        ssl_ca_certs=str(ca_certificate),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
    listener_socket = config.bind_socket()
    port = listener_socket.getsockname()[1]
    server = uvicorn.Server(config)
    server_errors: list[BaseException] = []

    def run_server() -> None:
        try:
            server.run(sockets=[listener_socket])
        except BaseException as exc:  # pragma: no cover - surfaced by fixture startup assertion
            server_errors.append(exc)

    thread = threading.Thread(target=run_server, name="form-agent-mtls-test", daemon=True)
    thread.start()
    deadline = time.monotonic() + 5.0
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not server_errors
    assert server.started, "Agent mTLS listener did not start"

    running = _RunningAgentListener(
        base_url=f"https://127.0.0.1:{port}",
        ca_certificate=ca_certificate,
        client_certificate=client_certificate,
        client_private_key=client_private_key,
        agent_id=bundle.identity.agent_id,
        target_id=bundle.identity.target_id,
        canonical_host_id=bundle.identity.canonical_host_id,
        generation=bundle.certificate.generation,
        repository=repository,
        upstream_requests=upstream_requests,
    )
    try:
        yield running
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        listener_socket.close()
        repository.close()
        assert not thread.is_alive(), "Agent mTLS listener did not stop"
        assert not server_errors


def test_listener_tls_handshake_requires_a_client_certificate(
    agent_listener: _RunningAgentListener,
) -> None:
    with (
        agent_listener.client_without_certificate() as client,
        pytest.raises(httpx.TransportError),
    ):
        client.get("/health")


def test_active_scoped_certificate_binds_trusted_provenance_and_hides_control_routes(
    agent_listener: _RunningAgentListener,
) -> None:
    with agent_listener.client() as client:
        assert client.get("/health").status_code == 200

        response = client.post(
            "/ingest/asset-report",
            json=_asset_report("report-mtls-provenance"),
        )
        assert response.status_code == 202, response.text

        # The certificate authenticates the Agent first; route-level scope
        # authorization then distinguishes a valid-but-under-scoped identity.
        wrong_scope = client.post("/ingest/trace-batch", json=_trace_batch())
        assert wrong_scope.status_code == 403
        assert wrong_scope.json()["detail"] == (
            "Agent identity is not authorized for trace-batch ingest"
        )

        assert client.get("/openapi.json").status_code == 404
        assert client.get("/scans").status_code == 404
        assert client.get("/agent-identities").status_code == 404

    assert len(agent_listener.upstream_requests) == 1
    upstream = agent_listener.upstream_requests[0]
    assert upstream.url.path == "/ingest/asset-report"
    assert upstream.headers["authorization"] == "Bearer internal-test-token"
    payload = json.loads(upstream.content)
    assert payload["source_agent_id"] == agent_listener.agent_id
    assert payload["source_target_id"] == agent_listener.target_id
    assert payload["host"]["host_id"] == agent_listener.canonical_host_id
    assert payload["vulnerabilities"][0]["affected_asset_id"] == agent_listener.canonical_host_id


def test_revocation_rejects_the_next_request_on_an_existing_mtls_client(
    agent_listener: _RunningAgentListener,
) -> None:
    with agent_listener.client() as client:
        accepted = client.post(
            "/ingest/asset-report",
            json=_asset_report("report-before-revoke"),
        )
        assert accepted.status_code == 202

        agent_listener.repository.revoke(
            agent_listener.agent_id,
            generation=agent_listener.generation,
        )

        rejected = client.post(
            "/ingest/asset-report",
            json=_asset_report("report-after-revoke"),
        )
        assert rejected.status_code == 401
        assert rejected.json()["detail"] == "Unknown, expired, or revoked Agent certificate"

    assert len(agent_listener.upstream_requests) == 1
