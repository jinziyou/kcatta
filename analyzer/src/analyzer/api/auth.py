"""Optional Form-to-Analyzer service authentication."""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)


async def require_internal_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    """Enforce the internal bearer token when ``ANALYZER_INTERNAL_TOKEN`` is set.

    Form is the sole runtime caller of Analyzer. Admin-facing authorization and
    Agent ingest credentials terminate at Form and must never be forwarded here.
    App startup normally rejects a missing token. Requests pass without one only
    in the explicit ``ANALYZER_ALLOW_INSECURE_NO_AUTH`` local-development mode.
    """
    expected: str | None = request.app.state.internal_token
    if not expected:
        return

    if credentials is None or not secrets.compare_digest(credentials.credentials, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token",
        )
