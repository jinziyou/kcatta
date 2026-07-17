"""Form boundary, token-scope, and analyzer-proxy tests."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from kcatta_form.analyzer_client import AnalyzerClient
from kcatta_form.api import create_app


def _asset_report() -> dict:
    return {
        "report_id": "report-form-1",
        "collected_at": "2026-07-10T00:00:00Z",
        "scanner_version": "0.1.0",
        "host": {
            "host_id": "host-1",
            "hostname": "node-1",
            "os": "Ubuntu 24.04",
        },
        "assets": [],
        "vulnerabilities": [],
    }


def _app(tmp_path: Path, handler):  # type: ignore[no-untyped-def]
    upstream = AnalyzerClient(
        "http://analyzer.internal:10068",
        "internal-secret",
        transport=httpx.MockTransport(handler),
    )
    return create_app(
        data_dir=tmp_path,
        api_token="admin-secret",
        ingest_token="agent-secret",
        metrics_token="metrics-secret",
        storage_backend="jsonl",
        analyzer_client=upstream,
    )


def test_health_public_and_tokens_are_scope_separated(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    with TestClient(_app(tmp_path, handler)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/scans").status_code == 401
        assert (
            client.get("/scans", headers={"Authorization": "Bearer agent-secret"}).status_code
            == 401
        )
        assert (
            client.get("/scans", headers={"Authorization": "Bearer admin-secret"}).status_code
            == 200
        )
        assert client.get("/metrics").status_code == 401
        assert (
            client.get("/metrics", headers={"Authorization": "Bearer admin-secret"}).status_code
            == 401
        )
        metrics = client.get("/metrics", headers={"Authorization": "Bearer metrics-secret"})
        assert metrics.status_code == 200
        assert metrics.headers["content-type"].startswith("text/plain")
        assert (
            client.post(
                "/ingest/asset-report",
                json=_asset_report(),
                headers={"Authorization": "Bearer admin-secret"},
            ).status_code
            == 401
        )


def test_partial_token_configuration_fails_closed(tmp_path: Path):
    with pytest.raises(RuntimeError, match="must either both be configured"):
        create_app(data_dir=tmp_path, api_token="control-only")


def test_missing_form_tokens_require_explicit_local_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("FORM_API_TOKEN", raising=False)
    monkeypatch.delenv("FORM_INGEST_TOKEN", raising=False)
    monkeypatch.setenv("FORM_ALLOW_INSECURE_NO_AUTH", "false")
    with pytest.raises(RuntimeError, match="FORM_API_TOKEN and FORM_INGEST_TOKEN are required"):
        create_app(data_dir=tmp_path)


def test_missing_analyzer_identity_fails_when_form_auth_is_enabled(tmp_path: Path):
    with pytest.raises(RuntimeError, match="ANALYZER_INTERNAL_TOKEN is required"):
        create_app(
            data_dir=tmp_path,
            api_token="control",
            ingest_token="ingest",
            analyzer_token="",
        )


def test_equal_trust_domain_tokens_fail_closed(tmp_path: Path):
    with pytest.raises(RuntimeError, match="FORM_INGEST_TOKEN must be distinct"):
        create_app(
            data_dir=tmp_path,
            api_token="shared",
            ingest_token="shared",
            analyzer_token="internal",
        )

    with pytest.raises(RuntimeError, match="ANALYZER_INTERNAL_TOKEN must be distinct"):
        create_app(
            data_dir=tmp_path,
            api_token="control",
            ingest_token="ingest",
            analyzer_token="ingest",
        )

    with pytest.raises(RuntimeError, match="FORM_METRICS_TOKEN must be distinct"):
        create_app(
            data_dir=tmp_path,
            api_token="control",
            ingest_token="ingest",
            metrics_token="control",
            analyzer_token="internal",
        )


def test_sqlite_control_state_uses_form_database_name(tmp_path: Path):
    upstream = AnalyzerClient(
        "http://analyzer.internal:10068",
        "internal-secret",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[])),
    )
    app = create_app(
        data_dir=tmp_path,
        storage_backend="sqlite",
        analyzer_client=upstream,
    )

    with TestClient(app) as client:
        assert client.get("/targets").status_code == 200

    assert (tmp_path / "form.db").is_file()
    assert not (tmp_path / "analyzer.db").exists()


def test_ready_checks_authenticated_analyzer_access(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/reports/asset-reports":
            assert request.headers["authorization"] == "Bearer internal-secret"
            return httpx.Response(401, json={"detail": "bad internal token"})
        return httpx.Response(200, json={"status": "ok"})

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.get("/ready", headers={"Authorization": "Bearer admin-secret"})

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["analyzer"] == "unavailable"
    assert body["worker"] == "ready"
    assert body["scheduler"] == "ready"


def test_agent_ingest_uses_internal_analyzer_identity(tmp_path: Path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.url.path == "/ingest/asset-report"
        return httpx.Response(202, json={"accepted": True, "id": "report-form-1"})

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.post(
            "/ingest/asset-report",
            json=_asset_report(),
            headers={
                "Authorization": "Bearer agent-secret",
                "X-Request-ID": "request-123",
            },
        )

    assert response.status_code == 202
    assert response.json() == {"accepted": True, "id": "report-form-1"}
    assert response.headers["x-request-id"] == "request-123"
    assert seen[0].headers["authorization"] == "Bearer internal-secret"
    assert seen[0].headers["x-request-id"] == "request-123"
    assert "agent-secret" not in seen[0].headers["authorization"]


def test_report_proxy_preserves_logical_pagination_header(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/reports/guard-events"
        assert request.url.params["page"] == "0"
        return httpx.Response(
            200,
            json=[],
            headers={
                "X-Kcatta-Has-More": "true",
                "X-Kcatta-Next-Cursor": "opaque-cursor",
            },
        )

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.get(
            "/reports/guard-events?page=0&limit=50",
            headers={"Authorization": "Bearer admin-secret"},
        )

    assert response.status_code == 200
    assert response.headers["x-kcatta-has-more"] == "true"
    assert response.headers["x-kcatta-next-cursor"] == "opaque-cursor"


def test_agent_ingest_rejects_unknown_fields_before_forwarding(tmp_path: Path):
    forwarded = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal forwarded
        forwarded = True
        return httpx.Response(202, json={"accepted": True, "id": "unexpected"})

    payload = _asset_report()
    payload["host"]["future_field"] = "must not be silently discarded"
    with TestClient(_app(tmp_path, handler)) as client:
        response = client.post(
            "/ingest/asset-report",
            json=payload,
            headers={"Authorization": "Bearer agent-secret"},
        )

    assert response.status_code == 422
    assert forwarded is False


def test_admin_query_is_restricted_proxy_and_preserves_status(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer internal-secret"
        if request.url.path.endswith("/missing"):
            return httpx.Response(404, json={"detail": "report not found"})
        return httpx.Response(200, json=[])

    with TestClient(_app(tmp_path, handler)) as client:
        headers = {"Authorization": "Bearer admin-secret"}
        assert client.get("/reports/asset-reports", headers=headers).json() == []
        missing = client.get("/reports/asset-reports/missing", headers=headers)
        assert missing.status_code == 404
        assert missing.json() == {"detail": "report not found"}


def test_analyzer_auth_failure_is_a_gateway_error_for_admin(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "bad internal token"})

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.get(
            "/reports/asset-reports",
            headers={"Authorization": "Bearer admin-secret"},
        )

    assert response.status_code == 502
    assert response.json()["detail"] == "Analyzer internal authorization failed"


def test_analyzer_outage_remains_transient_for_agent(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "internal-analyzer.example.test failed with token=private-value",
            request=request,
        )

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.post(
            "/ingest/asset-report",
            json=_asset_report(),
            headers={"Authorization": "Bearer agent-secret"},
        )
    assert response.status_code == 502
    assert response.json() == {"detail": "Analyzer unavailable"}
    assert "internal-analyzer" not in response.text
    assert "private-value" not in response.text


def test_analyzer_storage_capacity_is_preserved_as_retryable_507(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            507,
            headers={"Retry-After": "60"},
            json={"detail": "storage full"},
        )

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.post(
            "/ingest/asset-report",
            json=_asset_report(),
            headers={"Authorization": "Bearer agent-secret"},
        )
    assert response.status_code == 507
    assert response.headers["retry-after"] == "60"
    assert response.json() == {"detail": "Analyzer storage capacity is unavailable"}
    assert "storage full" not in response.text


def test_analyzer_payload_rejection_preserves_status_without_leaking_detail(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={"detail": "traceback: validation failed at /srv/analyzer/private.py"},
        )

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.post(
            "/ingest/asset-report",
            json=_asset_report(),
            headers={"Authorization": "Bearer agent-secret"},
        )

    assert response.status_code == 422
    assert response.json() == {"detail": "Analyzer rejected telemetry payload"}
    assert "traceback" not in response.text
    assert "/srv/analyzer" not in response.text


def test_analyzer_envelope_conflict_is_permanent_without_leaking_detail(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"detail": "private prior payload digest"})

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.post(
            "/ingest/asset-report",
            json=_asset_report(),
            headers={"Authorization": "Bearer agent-secret"},
        )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Telemetry envelope id conflicts with previously accepted content"
    }
    assert "digest" not in response.text


def test_internal_analyzer_auth_failure_does_not_deadletter_agent_data(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "bad internal token"})

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.post(
            "/ingest/asset-report",
            json=_asset_report(),
            headers={"Authorization": "Bearer agent-secret"},
        )
    assert response.status_code == 502


def test_proxy_rejects_encoded_dot_segment_before_upstream_request(tmp_path: Path):
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(202, json={"accepted": True, "id": "unexpected"})

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.post(
            "/reports/%252e%252e/%252e%252e/ingest/asset-report",
            json=_asset_report(),
            headers={"Authorization": "Bearer admin-secret"},
        )

    assert response.status_code == 400
    assert not called


def test_public_openapi_contains_form_owned_and_facade_routes(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    app = _app(tmp_path, handler)
    paths = set(app.openapi()["paths"])
    assert {
        "/targets",
        "/scans",
        "/scans/{job_id}/cancel",
        "/scans/{job_id}/retry",
        "/credentials",
        "/reports/{path}",
        "/attack-paths/{path}",
        "/ingest/asset-report",
    } <= paths


def test_analyzer_keeps_every_route_exposed_by_form_facade(tmp_path: Path):
    """Fail the monorepo build if Analyzer drifts behind Form/Admin's facade."""
    from analyzer.api import create_app as create_analyzer_app

    analyzer = create_analyzer_app(
        data_dir=tmp_path / "analyzer",
        osv_dir=tmp_path / "osv",
        storage_backend="jsonl",
        api_token="internal-contract",
    )
    actual = {
        (method.upper(), path)
        for path, operations in analyzer.openapi()["paths"].items()
        for method in operations
        if method in {"get", "post", "put", "patch", "delete"}
    }
    required = {
        ("GET", "/reports/asset-reports"),
        ("GET", "/reports/asset-reports/{report_id}"),
        ("GET", "/reports/trace-batches"),
        ("GET", "/reports/vulnerabilities"),
        ("GET", "/reports/vulnerabilities/{report_id}"),
        ("GET", "/reports/guard-events"),
        ("GET", "/reports/alerts"),
        ("GET", "/reports/alerts/export.csv"),
        ("GET", "/reports/alerts/{alert_id}"),
        ("POST", "/reports/alerts/{alert_key}/triage"),
        ("POST", "/detect/asset-report"),
        ("GET", "/attack-paths"),
        ("GET", "/attack-paths/{path_id}"),
    }
    assert required <= actual


def test_chunked_body_is_bounded_without_content_length(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("FORM_MAX_BODY_BYTES", "64")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"accepted": True, "id": "unexpected"})

    with TestClient(_app(tmp_path, handler)) as client:
        response = client.post(
            "/ingest/asset-report",
            content=(chunk for chunk in [b"{" + b"x" * 40, b"y" * 40 + b"}"]),
            headers={"Authorization": "Bearer agent-secret"},
        )

    assert response.status_code == 413
    assert "exceeds 64 bytes" in response.json()["detail"]


def test_chunked_unauthenticated_body_is_rejected_before_buffering(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("FORM_MAX_BODY_BYTES", "64")
    consumed = 0

    def chunks():
        nonlocal consumed
        for chunk in (b"x" * 40, b"y" * 40):
            consumed += 1
            yield chunk

    with TestClient(_app(tmp_path, lambda request: httpx.Response(202))) as client:
        response = client.post(
            "/ingest/asset-report",
            content=chunks(),
            headers={"Authorization": "Bearer wrong"},
        )

    assert response.status_code == 401
    # TestClient/httpx may consume one iterator chunk while constructing the
    # request, but Form must reject before draining the full over-limit stream.
    assert consumed < 2
