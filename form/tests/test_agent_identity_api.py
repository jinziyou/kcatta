from __future__ import annotations

from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from kcatta_form.analyzer_client import AnalyzerClient
from kcatta_form.api.agent_app import _principal_for_peer
from kcatta_form.api.app import create_app

CONTROL = {"Authorization": "Bearer control-secret"}


def _app(tmp_path: Path, monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("FORM_AGENT_IDENTITY_ENABLED", "true")
    monkeypatch.setenv("FORM_AGENT_PKI_DIR", str(tmp_path / "credentials" / "agent-pki"))
    monkeypatch.setenv("FORM_AGENT_TLS_DIR", str(tmp_path / "agent-tls"))
    upstream = AnalyzerClient(
        "http://analyzer.internal:10068",
        "internal-secret",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[])),
    )
    return create_app(
        data_dir=tmp_path / "data",
        api_token="control-secret",
        ingest_token="legacy-secret",
        agent_auth_mode="mixed",
        analyzer_client=upstream,
        storage_backend="sqlite",
    )


def test_provision_activate_authenticate_and_revoke_agent_identity(
    tmp_path: Path, monkeypatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        target_response = client.post(
            "/targets",
            headers=CONTROL,
            json={
                "name": "local-test",
                "address": "localhost",
                "transport": "local",
                "credential_mode": "none",
            },
        )
        assert target_response.status_code == 201
        target_id = target_response.json()["target_id"]

        issued = client.post(
            f"/targets/{target_id}/agent-identity/provision",
            headers=CONTROL,
            json={"scopes": ["guard-event"], "validity_days": 30},
        )
        assert issued.status_code == 201, issued.text
        bundle = issued.json()
        agent_id = bundle["identity"]["agent_id"]
        generation = bundle["certificate"]["generation"]
        fingerprint = bundle["certificate"]["cert_sha256"]
        serial = bundle["certificate"]["serial_number"]
        private_key = bundle["private_key_pem"]
        assert "BEGIN PRIVATE KEY" in private_key
        assert bundle["identity"]["canonical_host_id"] == target_id
        assert bundle["certificate"]["state"] == "staged"

        # Leaf private material is a one-time response, never durable registry data.
        assert (
            private_key.encode()
            not in (tmp_path / "data" / "form-agent-identities.db").read_bytes()
        )

        activated = client.post(
            f"/agent-identities/{agent_id}/activate",
            headers=CONTROL,
            json={"generation": generation},
        )
        assert activated.status_code == 200
        assert activated.json()["certificates"][0]["state"] == "active"

        principal = _principal_for_peer(
            app.state.agent_identity_service.repository,
            {"sha256": fingerprint, "serial": serial},
            "/ingest/guard-event",
        )
        assert principal is not None
        assert principal.agent_id == agent_id
        assert principal.target_id == target_id
        assert principal.scopes == ("guard-event",)
        wrong_route_principal = _principal_for_peer(
            app.state.agent_identity_service.repository,
            {"sha256": fingerprint, "serial": serial},
            "/ingest/trace-batch",
        )
        assert wrong_route_principal is not None
        assert "trace-batch" not in wrong_route_principal.scopes

        identities = client.get("/agent-identities", headers=CONTROL)
        assert identities.status_code == 200
        assert [item["agent_id"] for item in identities.json()] == [agent_id]

        revoked = client.post(
            f"/agent-identities/{agent_id}/revoke",
            headers=CONTROL,
            json={"generation": None},
        )
        assert revoked.status_code == 200
        assert revoked.json()["state"] == "revoked"
        assert (
            _principal_for_peer(
                app.state.agent_identity_service.repository,
                {"sha256": fingerprint, "serial": serial},
                "/ingest/guard-event",
            )
            is None
        )


def test_agent_identity_control_routes_require_control_token(tmp_path: Path, monkeypatch) -> None:
    with TestClient(_app(tmp_path, monkeypatch)) as client:
        assert client.get("/agent-identities").status_code == 401
        assert (
            client.get(
                "/agent-identities",
                headers={"Authorization": "Bearer legacy-secret"},
            ).status_code
            == 401
        )
