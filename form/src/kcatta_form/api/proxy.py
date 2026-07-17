"""Restricted Form facade over analyzer-owned query and ingest APIs."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BeforeValidator

from ..analyzer_client import AnalyzerClient, AnalyzerUpstreamError
from ..provenance import ProvenanceConflict, bind_agent_envelope
from ..schemas import AssetReport, CapabilityGraph, GuardEventBatch, TraceBatch
from .auth import require_api_token, require_ingest_token

query_router = APIRouter(dependencies=[Depends(require_api_token)])
ingest_router = APIRouter(prefix="/ingest", dependencies=[Depends(require_ingest_token)])
knowledge_router = APIRouter(prefix="/ingest", dependencies=[Depends(require_api_token)])
logger = logging.getLogger(__name__)


def _forbid_unknown(model):  # type: ignore[no-untyped-def]
    def validate(value: Any):  # type: ignore[no-untyped-def]
        return model.model_validate(value, extra="forbid")

    return validate


InboundAssetReport = Annotated[AssetReport, BeforeValidator(_forbid_unknown(AssetReport))]
InboundTraceBatch = Annotated[TraceBatch, BeforeValidator(_forbid_unknown(TraceBatch))]
InboundGuardEventBatch = Annotated[
    GuardEventBatch,
    BeforeValidator(_forbid_unknown(GuardEventBatch)),
]

_RESPONSE_HEADERS = {
    "content-disposition",
    "content-type",
    "x-alert-export-truncated",
    "x-kcatta-has-more",
    "x-kcatta-next-cursor",
    "x-request-id",
}


def _client(request: Request) -> AnalyzerClient:
    return request.app.state.analyzer_client


def _upstream_response(response) -> Response:  # type: ignore[no-untyped-def]
    headers = {
        name: value for name, value in response.headers.items() if name.lower() in _RESPONSE_HEADERS
    }
    return Response(content=response.content, status_code=response.status_code, headers=headers)


async def _proxy(request: Request, path: str) -> Response:
    try:
        response = await _client(request).request(
            request.method,
            path,
            params=list(request.query_params.multi_items()),
            content=await request.body() if request.method != "GET" else None,
            request_id=getattr(request.state, "request_id", None),
        )
    except AnalyzerUpstreamError as exc:
        logger.warning(
            "Analyzer proxy request failed (status=%s, request_id=%s)",
            exc.status_code,
            getattr(request.state, "request_id", None),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Analyzer unavailable",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid analyzer proxy path",
        ) from exc
    if response.status_code in {status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN}:
        # This is Form's service identity failing at the private hop, not the
        # Admin caller's credential. Present it as a gateway/configuration fault
        # and do not leak Analyzer's internal auth response.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Analyzer internal authorization failed",
        )
    return _upstream_response(response)


@query_router.get("/reports/{path:path}")
async def get_reports(path: str, request: Request) -> Response:
    return await _proxy(request, f"/reports/{path}")


@query_router.post("/reports/{path:path}")
async def post_reports(path: str, request: Request) -> Response:
    return await _proxy(request, f"/reports/{path}")


@query_router.get("/attack-paths")
async def proxy_attack_paths_root(request: Request) -> Response:
    return await _proxy(request, "/attack-paths")


@query_router.get("/attack-paths/{path:path}")
async def proxy_attack_paths(path: str, request: Request) -> Response:
    return await _proxy(request, f"/attack-paths/{path}")


@query_router.post("/detect/{path:path}")
async def proxy_detect(path: str, request: Request) -> Response:
    return await _proxy(request, f"/detect/{path}")


async def _ingest(request: Request, path: str, payload) -> Response:  # type: ignore[no-untyped-def]
    principal = getattr(request.state, "agent_principal", None)
    if principal is not None:
        scope = path.rsplit("/", 1)[-1]
        if scope not in set(principal.scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Agent identity is not authorized for {scope} ingest",
            )
        try:
            payload = bind_agent_envelope(
                payload,
                agent_id=principal.agent_id,
                target_id=principal.target_id,
                canonical_host_id=principal.canonical_host_id,
            )
        except ProvenanceConflict as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc
    elif hasattr(payload, "source_agent_id"):
        # The compatibility bearer authenticates only the old fleet-wide
        # scope.  It must never be allowed to mint trusted per-Agent provenance.
        payload = payload.model_copy(
            update={"source_agent_id": None, "source_target_id": None},
            deep=True,
        )
    try:
        response = await _client(request).ingest(
            path,
            payload,
            request_id=getattr(request.state, "request_id", None),
        )
    except AnalyzerUpstreamError as exc:
        # Only payload failures are permanent from the agent's perspective.
        # Internal 401/403/404 responses indicate a Form↔analyzer deployment
        # problem, so expose them as 502: agentd will retain the payload in its
        # durable spool instead of dead-lettering valid telemetry.
        code = exc.status_code if exc.status_code in {400, 409, 413, 422, 429, 507} else 502
        headers = {"Retry-After": "60"} if code == 507 else None
        detail = {
            400: "Analyzer rejected telemetry payload",
            409: "Telemetry envelope id conflicts with previously accepted content",
            413: "Telemetry payload exceeds Analyzer limits",
            422: "Analyzer rejected telemetry payload",
            429: "Analyzer is temporarily rate limited",
            507: "Analyzer storage capacity is unavailable",
        }.get(code, "Analyzer unavailable")
        logger.warning(
            "Analyzer ingest failed (status=%s, request_id=%s)",
            exc.status_code,
            getattr(request.state, "request_id", None),
        )
        return JSONResponse(
            status_code=code,
            headers=headers,
            content={"detail": detail},
        )
    return _upstream_response(response)


@ingest_router.post("/asset-report", status_code=status.HTTP_202_ACCEPTED)
async def ingest_asset_report(report: InboundAssetReport, request: Request) -> Response:
    return await _ingest(request, "/ingest/asset-report", report)


@ingest_router.post("/trace-batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_trace_batch(batch: InboundTraceBatch, request: Request) -> Response:
    return await _ingest(request, "/ingest/trace-batch", batch)


@ingest_router.post("/guard-event", status_code=status.HTTP_202_ACCEPTED)
async def ingest_guard_event(batch: InboundGuardEventBatch, request: Request) -> Response:
    return await _ingest(request, "/ingest/guard-event", batch)


@knowledge_router.post("/capability-graph", status_code=status.HTTP_202_ACCEPTED)
async def ingest_capability_graph(graph: CapabilityGraph, request: Request) -> Response:
    return await _ingest(request, "/ingest/capability-graph", graph)
