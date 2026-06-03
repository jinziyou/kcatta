"""Optional bearer-token auth for form HTTP endpoints."""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)


async def require_api_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """Enforce ``Authorization: Bearer <token>`` when ``FORM_API_TOKEN`` is set.

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
