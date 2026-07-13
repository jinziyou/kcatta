"""ASGI middleware used at Form's low-trust public edge."""

from __future__ import annotations

import asyncio
import math
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..mtls_protocol import peer_certificate_from_scope
from .auth import AgentPrincipal


@dataclass
class _TokenBucket:
    tokens: float
    updated_at: float


class BodySizeLimitMiddleware:
    """Bound authenticated edge concurrency, ingest rate, and body size.

    Agent credentials are deliberately lower-trust than the control token. A
    compromised endpoint can send chunked/HTTP2 data without Content-Length, so
    limits are applied before buffering and do not trust forwarding headers.
    """

    def __init__(
        self,
        app: ASGIApp,
        max_bytes: int,
        control_token: str | None = None,
        ingest_token: str | None = None,
        max_in_flight: int = 16,
        max_in_flight_per_peer: int = 8,
        max_ingest_in_flight_per_peer: int = 4,
        ingest_rate_per_second: float = 5.0,
        ingest_burst: int = 20,
        body_read_timeout_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        agent_auth_mode: str = "legacy",
        agent_authenticator: Callable[[dict[str, str], str], AgentPrincipal | None] | None = None,
    ) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if max_in_flight <= 0:
            raise ValueError("max_in_flight must be positive")
        if max_in_flight_per_peer <= 0:
            raise ValueError("max_in_flight_per_peer must be positive")
        if max_ingest_in_flight_per_peer <= 0:
            raise ValueError("max_ingest_in_flight_per_peer must be positive")
        if ingest_rate_per_second <= 0:
            raise ValueError("ingest_rate_per_second must be positive")
        if ingest_burst <= 0:
            raise ValueError("ingest_burst must be positive")
        if body_read_timeout_seconds <= 0:
            raise ValueError("body_read_timeout_seconds must be positive")
        self.app = app
        self.max_bytes = max_bytes
        self.control_token = control_token
        self.ingest_token = ingest_token
        self.max_in_flight = max_in_flight
        self.max_in_flight_per_peer = max_in_flight_per_peer
        self.max_ingest_in_flight_per_peer = max_ingest_in_flight_per_peer
        self.ingest_rate_per_second = ingest_rate_per_second
        self.ingest_burst = ingest_burst
        self.body_read_timeout_seconds = body_read_timeout_seconds
        self._clock = clock
        if agent_auth_mode not in {"legacy", "mixed", "mtls"}:
            raise ValueError("agent_auth_mode must be legacy, mixed, or mtls")
        self.agent_auth_mode = agent_auth_mode
        self.agent_authenticator = agent_authenticator
        self._lock = asyncio.Lock()
        self._in_flight = 0
        self._in_flight_by_peer: dict[str, int] = {}
        self._in_flight_by_agent: dict[str, int] = {}
        self._buckets: dict[tuple[str, bytes], _TokenBucket] = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        expected, detail, is_ingest = self._edge_token(scope)
        peer = self._peer(scope)
        agent_principal: AgentPrincipal | None = None
        if is_ingest and self.agent_auth_mode in {"mixed", "mtls"}:
            peer_certificate = peer_certificate_from_scope(scope)
            if peer_certificate is not None and self.agent_authenticator is not None:
                try:
                    agent_principal = self.agent_authenticator(
                        peer_certificate, str(scope.get("path", ""))
                    )
                except Exception:  # noqa: BLE001 - registry failure must fail closed at edge
                    await self._reject(
                        scope,
                        receive,
                        send,
                        503,
                        "Agent identity registry is unavailable",
                    )
                    return
            if peer_certificate is not None and agent_principal is None:
                admitted, retry_after = await self._admit_rejected_certificate(
                    peer,
                    peer_certificate.get("sha256", "unknown"),
                )
                if not admitted:
                    await self._reject(
                        scope,
                        receive,
                        send,
                        429,
                        "Form Agent authentication rate limit exceeded",
                        headers={"Retry-After": str(retry_after)},
                    )
                    return
                await self._reject(
                    scope,
                    receive,
                    send,
                    401,
                    "Unknown, expired, or revoked Agent certificate",
                )
                return
            if self.agent_auth_mode == "mtls" and agent_principal is None:
                await self._reject(
                    scope,
                    receive,
                    send,
                    401,
                    "A valid Agent client certificate is required",
                )
                return
            if agent_principal is not None:
                scope.setdefault("state", {})["agent_principal"] = agent_principal

        if (
            agent_principal is None
            and expected is not None
            and not self._authorized(headers, expected)
        ):
            # The streaming limiter must read a chunked body before it knows its
            # size. Authenticate at the edge first so an unauthenticated client
            # cannot force Form to buffer up to the limit per connection. Route
            # dependencies still enforce the same scope as the source of truth.
            await self._reject(scope, receive, send, 401, detail)
            return
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                declared = int(raw_length)
            except ValueError:
                await self._reject(scope, receive, send, 400, "invalid Content-Length")
                return
            if declared > self.max_bytes:
                await self._reject(scope, receive, send, 413, self._detail())
                return

        agent_id = agent_principal.agent_id if agent_principal is not None else None
        admitted, retry_after = await self._admit(peer, is_ingest, agent_id)
        if not admitted:
            await self._reject(
                scope,
                receive,
                send,
                429,
                "Form edge request limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )
            return

        released = False

        async def release_slot() -> None:
            nonlocal released
            async with self._lock:
                if released:
                    return
                released = True
                self._in_flight -= 1
                remaining = self._in_flight_by_peer.get(peer, 1) - 1
                if remaining > 0:
                    self._in_flight_by_peer[peer] = remaining
                else:
                    self._in_flight_by_peer.pop(peer, None)
                if agent_id is not None:
                    agent_remaining = self._in_flight_by_agent.get(agent_id, 1) - 1
                    if agent_remaining > 0:
                        self._in_flight_by_agent[agent_id] = agent_remaining
                    else:
                        self._in_flight_by_agent.pop(agent_id, None)

        async def response_send(message: Message) -> None:
            await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                # Starlette awaits BackgroundTasks after the final response body.
                # Admission protects request/body handling, not a scan worker that
                # has already returned 202 to the caller.
                await release_slot()

        try:
            if str(scope.get("method", "GET")).upper() in {"GET", "HEAD"} and expected is None:
                # Public metadata handlers never consume request bodies. Let them
                # answer immediately instead of buffering a tokenless chunked GET.
                await self.app(scope, receive, response_send)
                return

            # Buffer at the outer ASGI edge, stopping as soon as the limit is
            # crossed, then replay the bounded messages to FastAPI. Raising from
            # a wrapped ``receive`` is not sufficient: Starlette's body parser
            # turns that exception into a generic 400 before outer middleware can
            # map it to 413.
            buffered_body = bytearray()
            consumed = 0
            disconnected = False
            try:
                async with asyncio.timeout(self.body_read_timeout_seconds):
                    while True:
                        message = await receive()
                        if message["type"] == "http.request":
                            chunk = message.get("body", b"")
                            consumed += len(chunk)
                            if consumed > self.max_bytes:
                                await self._reject(scope, receive, send, 413, self._detail())
                                return
                            buffered_body.extend(chunk)
                            if not message.get("more_body", False):
                                break
                        elif message["type"] == "http.disconnect":
                            disconnected = True
                            break
            except TimeoutError:
                await self._reject(
                    scope,
                    receive,
                    send,
                    408,
                    "request body was not received within "
                    f"{self.body_read_timeout_seconds:g} seconds",
                )
                return

            # Collapse arbitrarily many transport chunks into one bounded ASGI
            # message. Retaining a dict per byte-sized chunk would let a valid
            # low-trust token amplify a 10 MiB body into gigabytes of Python
            # object overhead despite the byte limit.
            body = bytes(buffered_body)
            del buffered_body
            replayed = False

            async def replay_receive() -> Message:
                nonlocal replayed
                if not replayed:
                    replayed = True
                    if disconnected:
                        return {"type": "http.disconnect"}
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            await self.app(scope, replay_receive, response_send)
        finally:
            # Exceptions/disconnects may occur before a complete response body.
            await release_slot()

    def _edge_token(self, scope: Scope) -> tuple[str | None, str, bool]:
        path = str(scope.get("path", ""))
        method = str(scope.get("method", "GET")).upper()
        if method in {"GET", "HEAD"} and path in {
            "/health",
            "/openapi.json",
            "/docs",
            "/docs/oauth2-redirect",
            "/redoc",
        }:
            return None, "", False
        if path in {
            "/ingest/asset-report",
            "/ingest/trace-batch",
            "/ingest/guard-event",
        }:
            return self.ingest_token or None, "Invalid or missing Form ingest token", True
        return self.control_token or None, "Invalid or missing Form API token", False

    @staticmethod
    def _peer(scope: Scope) -> str:
        client = scope.get("client")
        return str(client[0]) if client else "unknown"

    async def _admit(
        self, peer: str, is_ingest: bool, agent_id: str | None = None
    ) -> tuple[bool, int]:
        """Fail fast rather than queueing memory-heavy body readers."""
        now = self._clock()
        async with self._lock:
            if self._in_flight >= self.max_in_flight:
                return False, 1
            if self._in_flight_by_peer.get(peer, 0) >= self.max_in_flight_per_peer:
                return False, 1
            if (
                is_ingest
                and self._in_flight_by_peer.get(peer, 0) >= self.max_ingest_in_flight_per_peer
            ):
                return False, 1
            if (
                is_ingest
                and agent_id is not None
                and self._in_flight_by_agent.get(agent_id, 0) >= self.max_ingest_in_flight_per_peer
            ):
                return False, 1

            if is_ingest:
                # Do not trust X-Forwarded-For at this public edge. Operators that
                # terminate at a trusted proxy should pass the real peer through
                # the ASGI server's trusted-proxy configuration.
                # There is one configured ingest scope per Form instance. Keying
                # on the raw Authorization header would let callers bypass the
                # bucket by changing the case of the Bearer scheme.
                # A verified certificate keeps one endpoint in the same bucket
                # even when its source IP changes, and separates endpoints that
                # share a NAT/proxy. Legacy fleet-token traffic retains the old
                # direct-peer key during migration.
                key = (agent_id or peer, b"agent" if agent_id else b"ingest")
                retry = self._consume_bucket_locked(key, now)
                if retry is not None:
                    return False, retry

            self._in_flight += 1
            self._in_flight_by_peer[peer] = self._in_flight_by_peer.get(peer, 0) + 1
            if agent_id is not None:
                self._in_flight_by_agent[agent_id] = self._in_flight_by_agent.get(agent_id, 0) + 1
            return True, 0

    async def _admit_rejected_certificate(
        self,
        peer: str,
        fingerprint: str,
    ) -> tuple[bool, int]:
        """Rate-limit revoked/unknown signed peers before another DB lookup cycle."""

        now = self._clock()
        key = (fingerprint or peer, b"agent-auth-rejected")
        async with self._lock:
            retry = self._consume_bucket_locked(key, now)
        return (retry is None, retry or 0)

    def _consume_bucket_locked(self, key: tuple[str, bytes], now: float) -> int | None:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _TokenBucket(float(self.ingest_burst), now)
            self._buckets[key] = bucket
        else:
            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(
                float(self.ingest_burst),
                bucket.tokens + elapsed * self.ingest_rate_per_second,
            )
            bucket.updated_at = now
        if bucket.tokens < 1.0:
            retry = math.ceil((1.0 - bucket.tokens) / self.ingest_rate_per_second)
            return max(1, retry)
        bucket.tokens -= 1.0

        # A finite CA issuance set bounds genuine certificate identities; cap
        # defensive state as well so rejected credentials cannot grow it forever.
        if len(self._buckets) > 4096:
            oldest = min(self._buckets, key=lambda item: self._buckets[item].updated_at)
            if oldest != key:
                self._buckets.pop(oldest, None)
        return None

    @staticmethod
    def _authorized(headers: dict[bytes, bytes], expected: str) -> bool:
        raw = headers.get(b"authorization", b"")
        try:
            scheme, presented = raw.decode("latin-1").split(" ", 1)
        except ValueError:
            return False
        return scheme.lower() == "bearer" and secrets.compare_digest(presented, expected)

    def _detail(self) -> str:
        return f"request body exceeds {self.max_bytes} bytes"

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
        status_code: int,
        detail: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        response = JSONResponse(
            status_code=status_code, content={"detail": detail}, headers=headers
        )
        await response(scope, receive, send)
