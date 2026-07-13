"""Validation for public origins embedded in remotely deployed Agent commands."""

from __future__ import annotations

from urllib.parse import urlsplit


def normalize_public_origin(
    value: str,
    *,
    label: str,
    allow_http: bool = False,
) -> str:
    """Return a canonical origin, rejecting every URL component beyond authority.

    Agent upload routes are appended by trusted code. Accepting a caller-supplied
    path, query, or fragment here would make that concatenation ambiguous and can
    redirect telemetry away from the intended ingest endpoint.
    """
    origin = value.strip()
    try:
        parsed = urlsplit(origin)
        # ``hostname`` and especially ``port`` perform validation that
        # ``urlsplit`` itself intentionally defers.
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as error:
        raise ValueError(f"{label} must be a valid public origin") from error

    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme.lower() not in allowed_schemes or not hostname:
        if allow_http:
            raise ValueError(f"{label} must be an absolute HTTP(S) origin with a host")
        raise ValueError(f"{label} must use HTTPS and be an absolute https:// origin with a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} must not contain userinfo")
    if "?" in origin or "#" in origin or parsed.query or parsed.fragment:
        raise ValueError(f"{label} must not contain a query or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError(f"{label} must be a pure origin; its path may only be empty or '/'")
    if "\\" in parsed.netloc or any(character.isspace() for character in parsed.netloc):
        raise ValueError(f"{label} contains an invalid host")
    if parsed.netloc.endswith(":"):
        raise ValueError(f"{label} contains an empty port")

    return origin[:-1] if parsed.path == "/" else origin
