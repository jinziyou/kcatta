"""Optional bearer-token auth for analyzer HTTP endpoints."""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)


async def require_api_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    """Enforce ``Authorization: Bearer <token>`` when ``ANALYZER_API_TOKEN`` is set.

    When no token is configured on the app, all requests pass through unchanged
    so local dev and existing tests keep working without headers.
    """
    expected: str | None = request.app.state.api_token
    if not expected:
        return

    if credentials is None or not secrets.compare_digest(credentials.credentials, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token",
        )


async def require_ingest_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    """Enforce the ingest-scoped token OR the master admin token on ``/ingest``.

    Guard/agent uploads carry a narrower ``ANALYZER_INGEST_TOKEN`` (distributed to
    monitored endpoints by :func:`analyzer.deploy.agent._install_guard_env`) that
    authorizes ``/ingest/*`` only — a compromised endpoint can forge telemetry but
    cannot reach ``/scans`` (remote exec) or ``/credentials``. The master
    ``ANALYZER_API_TOKEN`` remains a superset, so the admin UI and single-token
    deployments (where the ingest token defaults to the master) keep working.

    When neither token is configured the endpoint stays open (v0 dev default).
    """
    master: str | None = request.app.state.api_token
    ingest: str | None = getattr(request.app.state, "ingest_token", None) or master
    if not master and not ingest:
        return

    presented = credentials.credentials if credentials is not None else None
    if presented is not None and (
        (ingest is not None and secrets.compare_digest(presented, ingest))
        or (master is not None and secrets.compare_digest(presented, master))
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API token",
    )
