from __future__ import annotations

import os
import socket
import ssl
import threading
import time
from pathlib import Path
from queue import Queue

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from kcatta_form import agent_listener_runtime as listener_runtime
from kcatta_form import agent_runtime
from kcatta_form.agent_listener_runtime import (
    ListenerTlsMaterialError,
    load_listener_tls_material,
    run_reloadable_agent_listener,
)
from kcatta_form.schemas.agent_identity import AgentScope


def _configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORM_AGENT_PKI_DIR", str(tmp_path / "credentials" / "agent-pki"))
    monkeypatch.setenv("FORM_AGENT_TLS_DIR", str(tmp_path / "agent-tls"))
    monkeypatch.setenv("FORM_AGENT_IDENTITY_DATA_DIR", str(tmp_path / "agent-identities"))
    monkeypatch.setenv("FORM_AGENT_PUBLIC_URL", "https://agents.example.test:10443")


def test_listener_material_rejects_a_mismatched_private_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    other = service.certificate_authority.issue_server_certificate("agents.example.test")
    wrong_key = tmp_path / "wrong-key.pem"
    wrong_key.write_text(other.private_key_pem, encoding="ascii")

    try:
        with pytest.raises(ListenerTlsMaterialError, match="do not match"):
            load_listener_tls_material(
                paths.server_certificate,
                wrong_key,
                paths.ca_certificate,
            )
    finally:
        service.repository.close()


def test_listener_gracefully_recycles_and_loads_the_new_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    first_generation = paths.server_current.readlink()
    first_started = threading.Event()
    configurations: list[uvicorn.Config] = []

    class FakeServer:
        def __init__(self, config: uvicorn.Config) -> None:
            self.config = config
            self.should_exit = False
            self.external_exit_requested = False
            configurations.append(config)

        def run(self) -> None:
            if len(configurations) == 1:
                first_started.set()
                deadline = time.monotonic() + 2
                while not self.should_exit and time.monotonic() < deadline:
                    time.sleep(0.001)
                assert self.should_exit, "TLS watcher did not request a graceful recycle"
            else:
                self.external_exit_requested = True

    errors: list[BaseException] = []

    def serve() -> None:
        try:
            run_reloadable_agent_listener(
                host="127.0.0.1",
                port=10443,
                certificate=paths.server_certificate,
                private_key=paths.server_private_key,
                client_ca=paths.ca_certificate,
                poll_seconds=0.005,
                graceful_shutdown_seconds=7,
                server_factory=FakeServer,  # type: ignore[arg-type]
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert first_started.wait(timeout=2)
    issued = service.certificate_authority.issue_server_certificate("agents.example.test")
    agent_runtime._publish_server_generation(  # noqa: SLF001 - exercise atomic publication
        paths,
        issued.certificate_pem,
        issued.private_key_pem,
    )
    thread.join(timeout=3)

    try:
        assert not thread.is_alive()
        assert not errors
        assert len(configurations) == 2
        assert Path(configurations[0].ssl_certfile).parent.name == first_generation.name
        assert Path(configurations[1].ssl_certfile).parent == paths.server_current.resolve()
        assert configurations[0].ssl_certfile != configurations[1].ssl_certfile
        assert configurations[1].ssl_cert_reqs != 0
        assert configurations[1].proxy_headers is False
        assert configurations[1].timeout_graceful_shutdown == 7
    finally:
        service.repository.close()


def test_listener_ignores_an_incomplete_generation_until_a_valid_one_is_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    first_started = threading.Event()
    first_server: list[object] = []
    server_count = 0

    class FakeServer:
        def __init__(self, config: uvicorn.Config) -> None:
            nonlocal server_count
            server_count += 1
            self.should_exit = False
            self.external_exit_requested = False
            first_server.append(self)

        def run(self) -> None:
            if server_count == 1:
                first_started.set()
                deadline = time.monotonic() + 2
                while not self.should_exit and time.monotonic() < deadline:
                    time.sleep(0.001)
                assert self.should_exit
            else:
                self.external_exit_requested = True

    thread = threading.Thread(
        target=lambda: run_reloadable_agent_listener(
            host="127.0.0.1",
            port=10443,
            certificate=paths.server_certificate,
            private_key=paths.server_private_key,
            client_ca=paths.ca_certificate,
            poll_seconds=0.005,
            server_factory=FakeServer,  # type: ignore[arg-type]
        ),
        daemon=True,
    )
    thread.start()
    assert first_started.wait(timeout=2)

    bad_generation = paths.tls_directory / "generation-incomplete"
    bad_generation.mkdir(mode=0o700)
    (bad_generation / "server-cert.pem").write_bytes(paths.server_certificate.read_bytes())
    os.symlink(bad_generation.name, paths.tls_directory / ".bad-current")
    os.replace(paths.tls_directory / ".bad-current", paths.server_current)
    time.sleep(0.03)
    assert not first_server[0].should_exit  # type: ignore[attr-defined]

    issued = service.certificate_authority.issue_server_certificate("agents.example.test")
    agent_runtime._publish_server_generation(  # noqa: SLF001 - exercise recovery publication
        paths,
        issued.certificate_pem,
        issued.private_key_pem,
    )
    thread.join(timeout=3)

    try:
        assert not thread.is_alive()
        assert server_count == 2
    finally:
        service.repository.close()


def test_listener_watcher_keeps_lkg_after_unexpected_candidate_parser_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = listener_runtime.ListenerTlsMaterial(
        certificate=tmp_path / "current-cert.pem",
        private_key=tmp_path / "current-key.pem",
        client_ca=tmp_path / "ca.pem",
        stamp="current",
    )
    candidate = listener_runtime.ListenerTlsMaterial(
        certificate=tmp_path / "next-cert.pem",
        private_key=tmp_path / "next-key.pem",
        client_ca=tmp_path / "ca.pem",
        stamp="next",
    )
    calls = 0

    def flaky_loader(*_args: object) -> listener_runtime.ListenerTlsMaterial:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("cryptography backend failed unexpectedly")
        return candidate

    monkeypatch.setattr(listener_runtime, "load_listener_tls_material", flaky_loader)

    class FakeServer:
        should_exit = False

    server = FakeServer()
    stop = threading.Event()
    reload_requested = threading.Event()
    candidates: Queue[listener_runtime.ListenerTlsMaterial] = Queue(maxsize=1)
    watcher = threading.Thread(
        target=listener_runtime._watch_tls_material,  # noqa: SLF001 - availability unit
        args=(
            server,
            current,
            current.certificate,
            current.private_key,
            current.client_ca,
            stop,
            reload_requested,
            0.001,
            None,
            candidates,
        ),
        daemon=True,
    )
    watcher.start()
    watcher.join(timeout=1)
    stop.set()
    watcher.join(timeout=1)

    assert not watcher.is_alive()
    assert calls >= 2
    assert reload_requested.is_set()
    assert server.should_exit is True
    assert candidates.get_nowait() == candidate


def test_validated_generation_remains_lkg_if_current_turns_invalid_during_recycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    bad_generation = paths.tls_directory / "generation-racy-incomplete"
    bad_generation.mkdir(mode=0o700)
    (bad_generation / "server-cert.pem").write_bytes(paths.server_certificate.read_bytes())
    first_started = threading.Event()
    configurations: list[uvicorn.Config] = []
    errors: list[BaseException] = []

    class FakeServer:
        def __init__(self, config: uvicorn.Config) -> None:
            self.should_exit = False
            self.external_exit_requested = False
            configurations.append(config)

        def run(self) -> None:
            if len(configurations) == 1:
                first_started.set()
                deadline = time.monotonic() + 2
                while not self.should_exit and time.monotonic() < deadline:
                    time.sleep(0.001)
                assert self.should_exit
                os.symlink(bad_generation.name, paths.tls_directory / ".racy-current")
                os.replace(paths.tls_directory / ".racy-current", paths.server_current)
            else:
                self.external_exit_requested = True

    def serve() -> None:
        try:
            run_reloadable_agent_listener(
                host="127.0.0.1",
                port=10443,
                certificate=paths.server_certificate,
                private_key=paths.server_private_key,
                client_ca=paths.ca_certificate,
                poll_seconds=0.005,
                server_factory=FakeServer,  # type: ignore[arg-type]
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert first_started.wait(timeout=2)
    issued = service.certificate_authority.issue_server_certificate("agents.example.test")
    generations_before_publish = set(paths.tls_directory.glob("generation-*"))
    agent_runtime._publish_server_generation(  # noqa: SLF001 - exercise live publication
        paths,
        issued.certificate_pem,
        issued.private_key_pem,
    )
    # The fake server deliberately changes ``current`` as soon as the watcher
    # asks it to recycle. Identify the immutable generation created by this
    # publication instead of racing that second switch through ``current``.
    published_generations = (
        set(paths.tls_directory.glob("generation-*")) - generations_before_publish
    )
    assert len(published_generations) == 1
    validated_generation = published_generations.pop()
    thread.join(timeout=3)

    try:
        assert not thread.is_alive()
        assert not errors
        assert len(configurations) == 2
        assert Path(configurations[1].ssl_certfile).parent == validated_generation
        assert paths.server_current.resolve() == bad_generation
    finally:
        service.repository.close()


def test_real_listener_presents_the_rotated_server_certificate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv("ANALYZER_INTERNAL_TOKEN", "listener-rotation-test-token")
    service, paths = agent_runtime.load_or_create_agent_identity_service(tmp_path / "data")
    bundle = service.provision(
        "target-listener-rotation",
        "host-listener-rotation",
        [AgentScope.ASSET_REPORT],
        agent_id="agent-listener-rotation",
    )
    service.activate(bundle.identity.agent_id, bundle.certificate.generation)
    client_certificate = tmp_path / "client-cert.pem"
    client_private_key = tmp_path / "client-key.pem"
    client_certificate.write_text(bundle.certificate_pem, encoding="ascii")
    client_private_key.write_text(bundle.private_key_pem, encoding="ascii")

    context = ssl.create_default_context(cafile=str(paths.ca_certificate))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(client_certificate, client_private_key)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    shutdown_requested = threading.Event()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            run_reloadable_agent_listener(
                host="127.0.0.1",
                port=port,
                certificate=paths.server_certificate,
                private_key=paths.server_private_key,
                client_ca=paths.ca_certificate,
                poll_seconds=0.01,
                graceful_shutdown_seconds=2,
                shutdown_requested=shutdown_requested,
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    def peer_fingerprint() -> bytes:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=1) as connection,
            context.wrap_socket(connection, server_hostname="agents.example.test") as tls,
        ):
            certificate = tls.getpeercert(binary_form=True)
        assert certificate is not None
        return x509.load_der_x509_certificate(certificate).fingerprint(hashes.SHA256())

    thread = threading.Thread(target=serve, name="form-agent-real-rotation-test", daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    initial_fingerprint = None
    while time.monotonic() < deadline:
        try:
            initial_fingerprint = peer_fingerprint()
            break
        except (OSError, ssl.SSLError):
            time.sleep(0.01)
    assert initial_fingerprint is not None, errors

    issued = service.certificate_authority.issue_server_certificate("agents.example.test")
    expected_fingerprint = x509.load_pem_x509_certificate(
        issued.certificate_pem.encode("ascii")
    ).fingerprint(hashes.SHA256())
    agent_runtime._publish_server_generation(  # noqa: SLF001 - exercise live publication
        paths,
        issued.certificate_pem,
        issued.private_key_pem,
    )
    deadline = time.monotonic() + 5
    observed_fingerprint = None
    while time.monotonic() < deadline:
        try:
            observed_fingerprint = peer_fingerprint()
            if observed_fingerprint == expected_fingerprint:
                break
        except (OSError, ssl.SSLError):
            pass
        time.sleep(0.01)

    shutdown_requested.set()
    thread.join(timeout=5)
    try:
        assert initial_fingerprint != expected_fingerprint
        assert observed_fingerprint == expected_fingerprint
        assert not thread.is_alive()
        assert not errors
    finally:
        service.repository.close()
