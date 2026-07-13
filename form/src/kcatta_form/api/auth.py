"""Bearer-token scopes for Form's public control and ingest APIs."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AgentPrincipal:
    """Agent identity established from Form's verified mTLS certificate."""

    agent_id: str
    target_id: str
    canonical_host_id: str
    scopes: tuple[str, ...]
    certificate_id: str
    auth_method: str = "mtls"


def _matches(presented: str | None, expected: str | None) -> bool:
    return bool(
        presented is not None
        and expected is not None
        and secrets.compare_digest(presented, expected)
    )


async def require_api_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    """Authorize admin/control-plane calls with ``FORM_API_TOKEN``.

    An unset token keeps local development open. Production deployments should
    always configure a token.
    """
    expected: str | None = request.app.state.api_token
    if not expected:
        return
    presented = credentials.credentials if credentials is not None else None
    if not _matches(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Form API token",
        )


async def require_ingest_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    """Authorize agent uploads with the ingest-scoped token only.

    Control and ingest credentials are intentionally distinct whenever auth is
    enabled; startup rejects a partial one-token configuration.
    """
    # The outer edge middleware verifies the certificate against the durable
    # registry before it reads/buffers the request body.  Route auth repeats the
    # fail-closed presence check as the source of truth for FastAPI routing.
    if getattr(request.state, "agent_principal", None) is not None:
        return
    mode = getattr(request.app.state, "agent_auth_mode", "legacy")
    if mode == "mtls":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid, active Agent client certificate is required",
        )

    expected: str | None = request.app.state.ingest_token
    if not expected:
        if mode != "legacy":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid Agent identity is required",
            )
        return
    presented = credentials.credentials if credentials is not None else None
    if not _matches(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Form ingest token",
        )
