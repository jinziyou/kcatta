"""Form control API for per-target Agent identities and certificate lifecycle."""

from __future__ import annotations

from datetime import timedelta

from analyzer.schemas.common import StrictModel
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import Field

from ..agent_identity_store import (
    AgentCertificateNotFoundError,
    AgentIdentityConflictError,
    AgentIdentityNotFoundError,
)
from ..agent_pki import AgentIdentityService, AgentPkiError
from ..schemas import ScanTarget
from ..schemas.agent_identity import (
    AgentCertificateBundle,
    AgentIdentity,
    AgentScope,
)

router = APIRouter(tags=["agent-identities"])


class AgentProvisionRequest(StrictModel):
    """Least-privilege scopes and lifetime for a new staged generation."""

    scopes: list[AgentScope] = Field(default_factory=lambda: [AgentScope.GUARD_EVENT])
    validity_days: int = Field(default=30, ge=1, le=90)


class AgentGenerationRequest(StrictModel):
    """Select one immutable certificate generation for activation/abort."""

    generation: int = Field(ge=1)


class AgentRotateRequest(StrictModel):
    """Lifetime for a replacement generation; stable scopes cannot change."""

    validity_days: int = Field(default=30, ge=1, le=90)


class AgentRevokeRequest(StrictModel):
    """Revoke one generation, or the stable identity and every generation."""

    generation: int | None = Field(default=None, ge=1)


def _service(request: Request) -> AgentIdentityService:
    service = getattr(request.app.state, "agent_identity_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent identity management is not enabled on this Form instance",
        )
    return service


def _map_error(exc: Exception) -> HTTPException:
    if isinstance(exc, (AgentIdentityNotFoundError, AgentCertificateNotFoundError)):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, AgentIdentityConflictError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, (AgentPkiError, ValueError)):
        return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc))
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="identity error")


@router.get("/agent-identities", response_model=list[AgentIdentity])
async def list_agent_identities(request: Request) -> list[AgentIdentity]:
    return _service(request).repository.list()


@router.get("/agent-identities/{agent_id}", response_model=AgentIdentity)
async def get_agent_identity(agent_id: str, request: Request) -> AgentIdentity:
    try:
        return _service(request).repository.get(agent_id)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/targets/{target_id}/agent-identity", response_model=AgentIdentity)
async def get_target_agent_identity(target_id: str, request: Request) -> AgentIdentity:
    try:
        return _service(request).repository.get_by_target(target_id)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post(
    "/targets/{target_id}/agent-identity/provision",
    status_code=status.HTTP_201_CREATED,
    response_model=AgentCertificateBundle,
)
async def provision_target_agent_identity(
    target_id: str,
    payload: AgentProvisionRequest,
    request: Request,
) -> AgentCertificateBundle:
    """Issue one staged bundle; its private key is returned exactly once."""
    target_record = request.app.state.scan_target_store.find_one("target_id", target_id)
    if target_record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    target = ScanTarget.model_validate(target_record)
    try:
        return _service(request).provision(
            target.target_id,
            target.canonical_host_id or target.target_id,
            payload.scopes,
            validity=timedelta(days=payload.validity_days),
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post(
    "/agent-identities/{agent_id}/rotate",
    status_code=status.HTTP_201_CREATED,
    response_model=AgentCertificateBundle,
)
async def rotate_agent_identity(
    agent_id: str,
    payload: AgentRotateRequest,
    request: Request,
) -> AgentCertificateBundle:
    """Stage a replacement certificate without invalidating the active one."""
    service = _service(request)
    try:
        service.repository.get(agent_id)
        return service.issue_staged(
            agent_id,
            validity=timedelta(days=payload.validity_days),
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/agent-identities/{agent_id}/activate", response_model=AgentIdentity)
async def activate_agent_generation(
    agent_id: str,
    payload: AgentGenerationRequest,
    request: Request,
) -> AgentIdentity:
    """Commit a successfully installed generation; old active overlaps briefly."""
    try:
        return _service(request).activate(agent_id, payload.generation)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/agent-identities/{agent_id}/abort", response_model=AgentIdentity)
async def abort_agent_generation(
    agent_id: str,
    payload: AgentGenerationRequest,
    request: Request,
) -> AgentIdentity:
    """Discard a failed staged deployment without touching the old active cert."""
    try:
        return _service(request).abort(agent_id, payload.generation)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/agent-identities/{agent_id}/revoke", response_model=AgentIdentity)
async def revoke_agent_identity(
    agent_id: str,
    payload: AgentRevokeRequest,
    request: Request,
) -> AgentIdentity:
    """Immediately revoke one generation or the entire endpoint identity."""
    try:
        return _service(request).revoke(agent_id, generation=payload.generation)
    except Exception as exc:
        raise _map_error(exc) from exc
