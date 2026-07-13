"""Low-trust Form edge rate/concurrency limits run before request buffering."""

from __future__ import annotations

import asyncio

from starlette.responses import JSONResponse

from kcatta_form.api.auth import AgentPrincipal
from kcatta_form.api.middleware import BodySizeLimitMiddleware


async def _request(
    app: BodySizeLimitMiddleware,
    path: str,
    token: str,
    *,
    peer: str = "192.0.2.10",
    scheme: str = "Bearer",
    certificate_sha256: str | None = None,
) -> tuple[int, dict[bytes, bytes]]:
    messages = [{"type": "http.request", "body": b"{}", "more_body": False}]
    sent: list[dict] = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"authorization", f"{scheme} {token}".encode())],
        "client": (peer, 4242),
        "server": ("form", 10067),
    }
    if certificate_sha256 is not None:
        scope["extensions"] = {
            "kcatta.mtls": {
                "sha256": certificate_sha256,
                "serial": certificate_sha256,
            }
        }
    await app(
        scope,
        receive,
        send,
    )
    start = next(message for message in sent if message["type"] == "http.response.start")
    return start["status"], dict(start["headers"])


def test_ingest_token_bucket_shares_scope_refills_and_uses_direct_peer():
    now = [100.0]

    async def scenario() -> None:
        async def inner(scope, receive, send):
            await JSONResponse({"ok": True})(scope, receive, send)

        edge = BodySizeLimitMiddleware(
            inner,
            max_bytes=1024,
            control_token="control",
            ingest_token="fleet",
            max_in_flight=4,
            ingest_rate_per_second=1.0,
            ingest_burst=2,
            clock=lambda: now[0],
        )

        assert (await _request(edge, "/ingest/asset-report", "fleet"))[0] == 200
        assert (await _request(edge, "/ingest/trace-batch", "fleet"))[0] == 200
        limited, headers = await _request(edge, "/ingest/guard-event", "fleet")
        assert limited == 429
        assert headers[b"retry-after"] == b"1"
        # Bearer scheme casing is auth-equivalent and cannot create a fresh bucket.
        assert (await _request(edge, "/ingest/guard-event", "fleet", scheme="bEaReR"))[0] == 429

        # Control traffic has a separate scope and does not replenish/consume the
        # lower-trust ingest bucket.
        assert (await _request(edge, "/scans", "control"))[0] == 200
        assert (await _request(edge, "/ingest/guard-event", "fleet"))[0] == 429

        # Buckets use the ASGI peer, never an untrusted forwarding header.
        assert (await _request(edge, "/ingest/guard-event", "fleet", peer="198.51.100.9"))[0] == 200
        now[0] += 1.0
        assert (await _request(edge, "/ingest/guard-event", "fleet"))[0] == 200

    asyncio.run(scenario())


def test_mtls_identity_is_authenticated_before_body_and_gets_its_own_bucket():
    async def scenario() -> None:
        seen: list[str] = []

        async def inner(scope, receive, send):
            seen.append(scope["state"]["agent_principal"].agent_id)
            await JSONResponse({"ok": True})(scope, receive, send)

        def authenticate(certificate: dict[str, str], path: str) -> AgentPrincipal | None:
            fingerprint = certificate["sha256"]
            if fingerprint not in {"cert-a", "cert-b"}:
                return None
            agent = fingerprint.removeprefix("cert-")
            return AgentPrincipal(
                agent_id=f"agent-{agent}",
                target_id=f"target-{agent}",
                canonical_host_id=f"target-{agent}",
                scopes=(path.rsplit("/", 1)[-1],),
                certificate_id=f"credential-{agent}",
            )

        edge = BodySizeLimitMiddleware(
            inner,
            max_bytes=1024,
            ingest_token=None,
            agent_auth_mode="mtls",
            agent_authenticator=authenticate,
            ingest_rate_per_second=1.0,
            ingest_burst=1,
        )

        assert (
            await _request(
                edge,
                "/ingest/guard-event",
                "unused",
                certificate_sha256="cert-a",
            )
        )[0] == 200
        # A second Agent behind the same direct peer has a separate identity bucket.
        assert (
            await _request(
                edge,
                "/ingest/guard-event",
                "unused",
                certificate_sha256="cert-b",
            )
        )[0] == 200
        assert (
            await _request(
                edge,
                "/ingest/guard-event",
                "unused",
                certificate_sha256="cert-a",
            )
        )[0] == 429
        assert seen == ["agent-a", "agent-b"]

        # HTTP headers cannot stand in for transport metadata.
        assert (await _request(edge, "/ingest/guard-event", "unused"))[0] == 401
        assert (
            await _request(
                edge,
                "/ingest/guard-event",
                "unused",
                certificate_sha256="unknown",
            )
        )[0] == 401
        assert (
            await _request(
                edge,
                "/ingest/guard-event",
                "unused",
                certificate_sha256="unknown",
            )
        )[0] == 429

    asyncio.run(scenario())


def test_global_in_flight_limit_fails_fast_before_second_body_reader():
    async def scenario() -> None:
        started = asyncio.Event()
        both_started = asyncio.Event()
        release = asyncio.Event()
        entered = 0

        async def inner(scope, receive, send):
            nonlocal entered
            entered += 1
            started.set()
            if entered == 2:
                both_started.set()
            await release.wait()
            await JSONResponse({"ok": True})(scope, receive, send)

        edge = BodySizeLimitMiddleware(
            inner,
            max_bytes=1024,
            control_token="control",
            ingest_token="fleet",
            max_in_flight=2,
            max_in_flight_per_peer=1,
            ingest_rate_per_second=10.0,
            ingest_burst=10,
        )

        first = asyncio.create_task(_request(edge, "/scans", "control"))
        await started.wait()
        limited, headers = await _request(edge, "/scans", "control")
        assert limited == 429
        assert headers[b"retry-after"] == b"1"
        other_peer = asyncio.create_task(_request(edge, "/scans", "control", peer="198.51.100.20"))
        await both_started.wait()
        # Two distinct peers now consume the global cap.
        assert (await _request(edge, "/scans", "control", peer="203.0.113.30"))[0] == 429
        release.set()
        assert (await first)[0] == 200
        assert (await other_peer)[0] == 200

    asyncio.run(scenario())


def test_slow_chunked_body_times_out_and_releases_slot():
    async def scenario() -> None:
        async def inner(scope, receive, send):
            await JSONResponse({"ok": True})(scope, receive, send)

        edge = BodySizeLimitMiddleware(
            inner,
            max_bytes=1024,
            control_token="control",
            ingest_token="fleet",
            max_in_flight=1,
            max_in_flight_per_peer=1,
            ingest_rate_per_second=10.0,
            ingest_burst=10,
            body_read_timeout_seconds=0.01,
        )
        sent: list[dict] = []

        async def stalled_receive():
            await asyncio.Event().wait()

        async def send(message):
            sent.append(message)

        await edge(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "POST",
                "scheme": "https",
                "path": "/ingest/asset-report",
                "raw_path": b"/ingest/asset-report",
                "query_string": b"",
                "headers": [(b"authorization", b"Bearer fleet")],
                "client": ("192.0.2.77", 4242),
                "server": ("form", 10067),
            },
            stalled_receive,
            send,
        )
        start = next(message for message in sent if message["type"] == "http.response.start")
        assert start["status"] == 408
        # The timed-out reader released both global and per-peer admission state.
        assert edge._in_flight == 0
        assert edge._in_flight_by_peer == {}

    asyncio.run(scenario())


def test_slot_releases_after_response_body_before_background_work_finishes():
    async def scenario() -> None:
        response_sent = asyncio.Event()
        finish_background = asyncio.Event()
        calls = 0

        async def inner(scope, receive, send):
            nonlocal calls
            calls += 1
            await JSONResponse({"accepted": True})(scope, receive, send)
            if calls == 1:
                # Mirrors Starlette Response.__call__: final body is sent before
                # it awaits an arbitrary response background callback.
                response_sent.set()
                await finish_background.wait()

        edge = BodySizeLimitMiddleware(
            inner,
            max_bytes=1024,
            control_token="control",
            ingest_token="fleet",
            max_in_flight=1,
            max_in_flight_per_peer=1,
            ingest_rate_per_second=10.0,
            ingest_burst=10,
        )

        first = asyncio.create_task(_request(edge, "/scans", "control"))
        await response_sent.wait()
        # The first ASGI call is still awaiting background work, but its HTTP
        # response completed, so monitoring/control traffic must not be 429'd.
        assert (await _request(edge, "/scans/job-1", "control"))[0] == 200
        finish_background.set()
        assert (await first)[0] == 200

    asyncio.run(scenario())


def test_many_transport_chunks_are_collapsed_to_one_bounded_replay_message():
    async def scenario() -> None:
        replay_count = 0
        replay_body = bytearray()

        async def inner(scope, receive, send):
            nonlocal replay_count
            while True:
                message = await receive()
                assert message["type"] == "http.request"
                replay_count += 1
                replay_body.extend(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            await JSONResponse({"ok": True})(scope, receive, send)

        edge = BodySizeLimitMiddleware(
            inner,
            max_bytes=4096,
            control_token="control",
            ingest_token="fleet",
            max_in_flight=2,
            max_in_flight_per_peer=1,
            ingest_rate_per_second=10.0,
            ingest_burst=10,
        )
        chunks = [
            {"type": "http.request", "body": b"x", "more_body": index < 2047}
            for index in range(2048)
        ]
        sent: list[dict] = []

        async def receive():
            return chunks.pop(0)

        async def send(message):
            sent.append(message)

        await edge(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "POST",
                "scheme": "https",
                "path": "/ingest/asset-report",
                "raw_path": b"/ingest/asset-report",
                "query_string": b"",
                "headers": [(b"authorization", b"Bearer fleet")],
                "client": ("192.0.2.88", 4242),
                "server": ("form", 10067),
            },
            receive,
            send,
        )

        assert replay_count == 1
        assert replay_body == b"x" * 2048
        assert (
            next(message for message in sent if message["type"] == "http.response.start")["status"]
            == 200
        )

    asyncio.run(scenario())
