from __future__ import annotations

import hashlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from kcatta_form.agent_identity_store import (
    AgentIdentityConflictError,
    AgentIdentityRepository,
)
from kcatta_form.schemas.agent_identity import (
    AgentCertificateState,
    AgentIdentityState,
    AgentScope,
)

NOW = datetime(2026, 7, 13, 8, 0, tzinfo=UTC)


def _fingerprint(kind: str, tag: int) -> str:
    return hashlib.sha256(f"{kind}-{tag}".encode()).hexdigest()


def _stage(
    repository: AgentIdentityRepository,
    agent_id: str,
    generation: int,
    tag: int,
    *,
    key: str | None = None,
    now: datetime = NOW,
):  # type: ignore[no-untyped-def]
    return repository.stage_certificate(
        agent_id,
        generation=generation,
        serial_number=format(tag + 1, "x"),
        cert_sha256=_fingerprint("cert", tag),
        spki_sha256=_fingerprint("spki", tag),
        certificate_pem=f"-----BEGIN CERTIFICATE-----\npublic-{tag}\n-----END CERTIFICATE-----",
        not_before=NOW - timedelta(minutes=5),
        not_after=NOW + timedelta(days=1),
        idempotency_key=key,
        now=now,
    )


def test_stable_target_host_scope_binding_and_inventory(tmp_path: Path) -> None:
    repository = AgentIdentityRepository(tmp_path)

    identity, created = repository.get_or_create(
        "target-1",
        "host-1",
        [AgentScope.TRACE_BATCH, AgentScope.ASSET_REPORT, AgentScope.TRACE_BATCH],
        now=NOW,
    )
    replay, replay_created = repository.get_or_create(
        "target-1",
        "host-1",
        [AgentScope.ASSET_REPORT, AgentScope.TRACE_BATCH],
        now=NOW + timedelta(hours=1),
    )

    assert created is True
    assert replay_created is False
    assert replay.agent_id == identity.agent_id
    assert replay.updated_at == NOW
    assert replay.scopes == [AgentScope.ASSET_REPORT, AgentScope.TRACE_BATCH]
    assert repository.get(identity.agent_id) == identity
    assert repository.get_by_target("target-1").agent_id == identity.agent_id
    assert [item.agent_id for item in repository.list()] == [identity.agent_id]

    with pytest.raises(AgentIdentityConflictError, match="canonical_host_id"):
        repository.get_or_create(
            "target-1",
            "host-other",
            identity.scopes,
            now=NOW,
        )
    with pytest.raises(AgentIdentityConflictError, match="scopes"):
        repository.get_or_create(
            "target-1",
            "host-1",
            [AgentScope.GUARD_EVENT],
            now=NOW,
        )
    with pytest.raises(AgentIdentityConflictError, match="already bound"):
        repository.get_or_create(
            "target-other",
            "host-1",
            [AgentScope.ASSET_REPORT, AgentScope.TRACE_BATCH],
            now=NOW,
        )


def test_abort_keeps_active_and_rotation_has_bounded_dual_certificate_window(
    tmp_path: Path,
) -> None:
    repository = AgentIdentityRepository(tmp_path)
    identity, _ = repository.get_or_create(
        "target-1",
        "host-1",
        [AgentScope.ASSET_REPORT],
        now=NOW,
    )

    staged_one, created = _stage(repository, identity.agent_id, 1, 10)
    assert created is True
    cert_one = staged_one.certificates[0]
    assert repository.verify(cert_sha256=cert_one.cert_sha256, now=NOW) is None
    assert (
        repository.verify(
            cert_sha256=cert_one.cert_sha256,
            now=NOW,
            allow_staged=True,
        ).agent_id
        == identity.agent_id
    )
    repository.activate(identity.agent_id, 1, now=NOW)
    assert repository.verify(serial_number=cert_one.serial_number, now=NOW) is not None

    staged_two, _ = _stage(
        repository,
        identity.agent_id,
        2,
        20,
        now=NOW + timedelta(minutes=1),
    )
    cert_two = staged_two.certificates[1]
    repository.abort(identity.agent_id, 2, now=NOW + timedelta(minutes=2))
    assert repository.get_certificate(identity.agent_id, 2).state is AgentCertificateState.REVOKED
    assert repository.verify(cert_sha256=cert_two.cert_sha256, now=NOW) is None
    # Aborting an uninstalled generation never retires or revokes the old active leaf.
    assert repository.verify(cert_sha256=cert_one.cert_sha256, now=NOW) is not None

    staged_three, _ = _stage(
        repository,
        identity.agent_id,
        3,
        30,
        now=NOW + timedelta(minutes=3),
    )
    cert_three = staged_three.certificates[2]
    activated = repository.activate(
        identity.agent_id,
        3,
        overlap=timedelta(minutes=5),
        now=NOW + timedelta(minutes=4),
    )
    assert activated.certificates[0].state is AgentCertificateState.RETIRED
    assert activated.certificates[2].state is AgentCertificateState.ACTIVE
    assert repository.verify(cert_sha256=cert_one.cert_sha256, now=NOW + timedelta(minutes=5))
    assert repository.verify(cert_sha256=cert_three.cert_sha256, now=NOW + timedelta(minutes=5))
    assert (
        repository.verify(cert_sha256=cert_one.cert_sha256, now=NOW + timedelta(minutes=9)) is None
    )
    # Both identifiers must describe the same certificate.
    assert (
        repository.verify(
            cert_sha256=cert_three.cert_sha256,
            serial_number=cert_one.serial_number,
            now=NOW + timedelta(minutes=5),
        )
        is None
    )

    certificate_revoked = repository.revoke(
        identity.agent_id,
        generation=3,
        now=NOW + timedelta(minutes=10),
    )
    assert certificate_revoked.state is AgentIdentityState.ACTIVE
    assert repository.verify(cert_sha256=cert_three.cert_sha256, now=NOW) is None
    identity_revoked = repository.revoke(identity.agent_id, now=NOW + timedelta(minutes=11))
    assert identity_revoked.state is AgentIdentityState.REVOKED
    assert repository.verify(serial_number=cert_three.serial_number, now=NOW) is None


def test_idempotency_key_is_hashed_and_abort_releases_it_for_next_generation(
    tmp_path: Path,
) -> None:
    repository = AgentIdentityRepository(tmp_path)
    identity, _ = repository.get_or_create(
        "target-1",
        "host-1",
        [AgentScope.GUARD_EVENT],
        now=NOW,
    )
    key = "scan-job-secret-123"

    first, first_created = _stage(repository, identity.agent_id, 1, 100, key=key)
    replay, replay_created = _stage(repository, identity.agent_id, 2, 101, key=key)
    assert first_created is True
    assert replay_created is False
    assert replay.generation == 1
    assert replay.certificates[0].cert_sha256 == first.certificates[0].cert_sha256

    with sqlite3.connect(repository.db_path) as connection:
        stored_hash = connection.execute(
            "SELECT idempotency_key_sha256 FROM agent_certificates WHERE generation = 1"
        ).fetchone()[0]
    assert stored_hash == hashlib.sha256(key.encode()).hexdigest()
    assert key.encode() not in repository.db_path.read_bytes()

    repository.abort(identity.agent_id, 1, now=NOW + timedelta(minutes=1))
    second, second_created = _stage(
        repository,
        identity.agent_id,
        2,
        102,
        key=key,
        now=NOW + timedelta(minutes=2),
    )
    assert second_created is True
    repository.activate(identity.agent_id, 2, now=NOW + timedelta(minutes=3))
    # Successful activation retains the reservation, preventing duplicate issuance.
    active_replay, active_created = _stage(
        repository,
        identity.agent_id,
        3,
        103,
        key=key,
        now=NOW + timedelta(minutes=4),
    )
    assert active_created is False
    assert active_replay.generation == 2
    assert active_replay.certificates[1].state is AgentCertificateState.ACTIVE


def test_guard_credential_teardown_preserves_identity_for_restart(tmp_path: Path) -> None:
    repository = AgentIdentityRepository(tmp_path)
    identity, _ = repository.get_or_create(
        "target-guard",
        "host-guard",
        [AgentScope.GUARD_EVENT],
        now=NOW,
    )
    staged, _ = _stage(repository, identity.agent_id, 1, 120, key="guard-start-1")
    first = staged.certificates[0]
    repository.activate(identity.agent_id, 1, now=NOW)

    stopped = repository.revoke_certificates(
        identity.agent_id,
        now=NOW + timedelta(minutes=1),
    )

    assert stopped.state is AgentIdentityState.ACTIVE
    assert stopped.certificates[0].state is AgentCertificateState.REVOKED
    assert repository.verify(cert_sha256=first.cert_sha256, now=NOW) is None

    restarted, created = _stage(
        repository,
        identity.agent_id,
        2,
        121,
        key="guard-start-2",
        now=NOW + timedelta(minutes=2),
    )
    assert created is True
    assert restarted.certificates[1].state is AgentCertificateState.STAGED


def test_concurrent_staging_is_serialized_and_same_key_is_idempotent(tmp_path: Path) -> None:
    first_repository = AgentIdentityRepository(tmp_path)
    second_repository = AgentIdentityRepository(tmp_path)
    identity, _ = first_repository.get_or_create(
        "target-1",
        "host-1",
        [AgentScope.TRACE_BATCH],
        now=NOW,
    )
    barrier = threading.Barrier(2)

    def stage(repository: AgentIdentityRepository, tag: int):  # type: ignore[no-untyped-def]
        barrier.wait(timeout=5)
        return _stage(repository, identity.agent_id, 1, tag, key="job-1")

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(stage, first_repository, 200),
            executor.submit(stage, second_repository, 201),
        ]
        results = [future.result(timeout=10) for future in futures]

    assert sorted(created for _identity, created in results) == [False, True]
    durable = first_repository.get(identity.agent_id)
    assert durable.generation == 1
    assert len(durable.certificates) == 1
    assert all(
        item.certificates[0].cert_sha256 == durable.certificates[0].cert_sha256
        for item, _created in results
    )

    first_repository.abort(identity.agent_id, 1, now=NOW + timedelta(minutes=1))
    barrier = threading.Barrier(2)

    def conflicting_stage(repository: AgentIdentityRepository, tag: int, key: str) -> str:
        barrier.wait(timeout=5)
        try:
            _stage(repository, identity.agent_id, 2, tag, key=key)
        except AgentIdentityConflictError:
            return "conflict"
        return "created"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = [
            executor.submit(conflicting_stage, first_repository, 210, "job-a"),
            executor.submit(conflicting_stage, second_repository, 211, "job-b"),
        ]
        assert sorted(future.result(timeout=10) for future in outcomes) == [
            "conflict",
            "created",
        ]
