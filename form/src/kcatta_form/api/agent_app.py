"""Dedicated mTLS-only Agent ingest application.

The control application and this listener are two processes of the same Form
component.  They share the transactional identity database, while this process
has no Admin control token, target deployment credentials, or CA signing key.
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..agent_identity_store import AgentIdentityRepository
from ..analyzer_client import AnalyzerClient
from .app import (
    DEFAULT_ANALYZER_URL,
    DEFAULT_BODY_READ_TIMEOUT_SECONDS,
    DEFAULT_INGEST_BURST,
    DEFAULT_INGEST_RATE_PER_SECOND,
    DEFAULT_MAX_IN_FLIGHT,
    DEFAULT_MAX_IN_FLIGHT_PER_PEER,
    DEFAULT_MAX_INGEST_IN_FLIGHT_PER_PEER,
    _data_dir,
    _max_body_bytes,
    _positive_float_env,
    _positive_int_env,
    _timeout,
)
from .auth import AgentPrincipal
from .middleware import BodySizeLimitMiddleware
from .proxy import ingest_router

logger = logging.getLogger("kcatta_form.api.agent")


def _principal_for_peer(
    repository: AgentIdentityRepository,
    peer_certificate: dict[str, str],
    _path: str,
) -> AgentPrincipal | None:
    try:
        verified = repository.verify(
            cert_sha256=peer_certificate.get("sha256"),
            serial_number=peer_certificate.get("serial"),
        )
    except ValueError:
        return None
    if verified is None:
        return None
    scopes = tuple(scope.value for scope in verified.scopes)
    return AgentPrincipal(
        agent_id=verified.agent_id,
        target_id=verified.target_id,
        canonical_host_id=verified.canonical_host_id,
        scopes=scopes,
        certificate_id=f"{verified.agent_id}:{verified.certificate.generation}",
    )


def create_agent_app(
    data_dir: Path | None = None,
    *,
    analyzer_url: str | None = None,
    analyzer_token: str | None = None,
    analyzer_client: AnalyzerClient | None = None,
) -> FastAPI:
    """Create the route-minimal Agent-facing half of Form."""
    directory = data_dir if data_dir is not None else _data_dir()
    token = (
        analyzer_token if analyzer_token is not None else os.getenv("ANALYZER_INTERNAL_TOKEN") or ""
    ).strip() or None
    if analyzer_client is None and token is None:
        raise RuntimeError("ANALYZER_INTERNAL_TOKEN is required for the Agent mTLS listener")
    client = analyzer_client or AnalyzerClient(
        analyzer_url or os.getenv("FORM_ANALYZER_BASE_URL", DEFAULT_ANALYZER_URL),
        token,
        timeout=_timeout(),
    )
    identity_data_dir = Path(os.getenv("FORM_AGENT_IDENTITY_DATA_DIR", str(directory)))
    repository = AgentIdentityRepository(identity_data_dir)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await app.state.analyzer_client.close()
            app.state.agent_identity_repository.close()

    app = FastAPI(
        title="kcatta Form Agent Ingest",
        version="0.1.0",
        description="mTLS-only Agent ingress of the Form orchestration boundary.",
        lifespan=lifespan,
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
    )
    app.state.api_token = None
    app.state.ingest_token = None
    app.state.agent_auth_mode = "mtls"
    app.state.analyzer_client = client
    app.state.agent_identity_repository = repository

    @app.middleware("http")
    async def request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

    app.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=_max_body_bytes(),
        control_token=None,
        ingest_token=None,
        max_in_flight=_positive_int_env("FORM_MAX_IN_FLIGHT", DEFAULT_MAX_IN_FLIGHT),
        max_in_flight_per_peer=_positive_int_env(
            "FORM_MAX_IN_FLIGHT_PER_PEER", DEFAULT_MAX_IN_FLIGHT_PER_PEER
        ),
        max_ingest_in_flight_per_peer=_positive_int_env(
            "FORM_MAX_INGEST_IN_FLIGHT_PER_PEER", DEFAULT_MAX_INGEST_IN_FLIGHT_PER_PEER
        ),
        ingest_rate_per_second=_positive_float_env(
            "FORM_INGEST_RATE_PER_SECOND", DEFAULT_INGEST_RATE_PER_SECOND
        ),
        ingest_burst=_positive_int_env("FORM_INGEST_BURST", DEFAULT_INGEST_BURST),
        body_read_timeout_seconds=_positive_float_env(
            "FORM_BODY_READ_TIMEOUT_SECONDS", DEFAULT_BODY_READ_TIMEOUT_SECONDS
        ),
        agent_auth_mode="mtls",
        agent_authenticator=lambda certificate, path: _principal_for_peer(
            repository, certificate, path
        ),
    )

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready", tags=["meta"])
    async def ready() -> JSONResponse:
        analyzer_ready = await app.state.analyzer_client.ready()
        return JSONResponse(
            status_code=200 if analyzer_ready else 503,
            content={
                "status": "ready" if analyzer_ready else "degraded",
                "analyzer": "ready" if analyzer_ready else "unavailable",
                "identity_registry": "ready",
            },
        )

    # Deliberately no targets/scans/query/capability-graph routes here. TLS
    # clients can submit only the three endpoint telemetry envelopes.
    app.include_router(ingest_router)
    return app
