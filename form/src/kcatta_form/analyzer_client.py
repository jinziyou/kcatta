"""Private HTTP client used exclusively for Form -> analyzer calls."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote

import httpx
from analyzer.schemas import AssetReport, TraceBatch
from pydantic import BaseModel

from .telemetry_chunks import split_asset_report, split_trace_batch


class AnalyzerUpstreamError(RuntimeError):
    """The private analyzer API was unreachable or rejected a request."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AnalyzerClient:
    """Small allow-by-call-site client for analyzer's private API.

    Incoming admin/agent authorization is never forwarded. Form authenticates
    every private call with ``ANALYZER_INTERNAL_TOKEN`` instead.
    """

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        normalized = base_url.strip().rstrip("/")
        parsed = httpx.URL(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.host:
            raise ValueError("FORM_ANALYZER_BASE_URL must be an absolute HTTP(S) URL")
        self.base_url = normalized
        self._token = token.strip() if token and token.strip() else None
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport)

    async def close(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | list[tuple[str, str]] | None = None,
        content: bytes | None = None,
        json: Any = None,
        request_id: str | None = None,
    ) -> httpx.Response:
        _validate_upstream_path(path)
        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if request_id:
            headers["X-Request-ID"] = request_id
        if content is not None or json is not None:
            headers["Content-Type"] = "application/json"
        try:
            return await self._client.request(
                method,
                f"{self.base_url}{path}",
                params=params,
                content=content,
                json=json,
                headers=headers,
            )
        except httpx.RequestError as exc:
            raise AnalyzerUpstreamError(f"analyzer unavailable: {exc}") from exc

    async def ingest(
        self, path: str, payload: BaseModel, *, request_id: str | None = None
    ) -> httpx.Response:
        response = await self.request(
            "POST",
            path,
            json=payload.model_dump(mode="json"),
            request_id=request_id,
        )
        if response.status_code != 202:
            detail = response.text[:2048]
            raise AnalyzerUpstreamError(
                f"analyzer ingest {path} failed ({response.status_code}): {detail}",
                status_code=response.status_code,
            )
        return response

    async def ingest_asset_report(self, report: AssetReport) -> httpx.Response:
        first: httpx.Response | None = None
        for chunk in split_asset_report(report):
            response = await self.ingest("/ingest/asset-report", chunk)
            if first is None:
                first = response
        assert first is not None  # splitters always return at least one child
        return first

    async def ingest_trace_batch(self, batch: TraceBatch) -> httpx.Response:
        first: httpx.Response | None = None
        for chunk in split_trace_batch(batch):
            response = await self.ingest("/ingest/trace-batch", chunk)
            if first is None:
                first = response
        assert first is not None  # splitters always return at least one child
        return first

    async def health(self) -> bool:
        try:
            response = await self.request("GET", "/health")
        except AnalyzerUpstreamError:
            return False
        return response.status_code == 200

    async def ready(self) -> bool:
        """Check an authenticated Analyzer route, including token and storage readiness."""
        try:
            response = await self.request("GET", "/reports/asset-reports", params={"limit": "1"})
        except AnalyzerUpstreamError:
            return False
        return response.status_code == 200


def _validate_upstream_path(path: str) -> None:
    """Reject paths that URL normalization could move outside an allowed facade prefix.

    Proxy suffixes originate in a public catch-all route. ``httpx`` normalizes
    dot segments before sending, so an encoded ``../`` could otherwise turn a
    Form control-token request for ``/reports/...`` into an authenticated call
    to an arbitrary Analyzer route. Decode repeatedly to also catch nested
    percent encoding before the URL client sees it.
    """
    if not path.startswith("/") or path.startswith("//") or "//" in path:
        raise ValueError(f"analyzer path must be one absolute normalized path: {path!r}")
    decoded = path
    for _ in range(4):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if any(ord(char) < 0x20 for char in decoded) or "\\" in decoded:
        raise ValueError("analyzer path contains forbidden characters")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError("analyzer path contains a forbidden dot segment")
