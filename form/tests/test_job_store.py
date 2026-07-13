"""Transactional scan-job claim, fencing, retry, cancel and migration semantics."""

from __future__ import annotations

import multiprocessing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty

import pytest
from analyzer.storage import StorageCapacityError

from kcatta_form.job_store import (
    ClaimedScanJob,
    JobConflictError,
    LeaseLostError,
    ScanJobRepository,
)
from kcatta_form.schemas import ScanCapability, ScanJob, ScanJobState

NOW = datetime(2026, 7, 10, 8, 0, tzinfo=UTC)


def _job(job_id: str, state: ScanJobState = ScanJobState.PENDING) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.HOST,
        state=state,
        created_at=NOW,
    )


def _job_for_target(job_id: str, target_id: str) -> ScanJob:
    job = _job(job_id)
    job.target_id = target_id
    return job


def _claim_in_process(
    data_dir: str,
    barrier: multiprocessing.synchronize.Barrier,
    output: multiprocessing.queues.Queue,
) -> None:
    repository = ScanJobRepository(Path(data_dir))
    barrier.wait(timeout=10)
    claim = repository.claim_next("child", NOW, timedelta(seconds=30), 4)
    output.put(claim.job.job_id if claim else None)
    repository.close()


def _renew_job_in_process(
    data_dir: str,
    claim: ClaimedScanJob,
    barrier: multiprocessing.synchronize.Barrier,
    output: multiprocessing.queues.Queue,
) -> None:
    repository = ScanJobRepository(Path(data_dir))
    barrier.wait(timeout=10)
    try:
        repository.renew(
            claim,
            NOW + timedelta(seconds=9),
            timedelta(seconds=30),
        )
    except LeaseLostError:
        renewed = False
    else:
        renewed = True
    output.put(("job", renewed))
    repository.close()


def _acquire_direct_operation_in_process(
    data_dir: str,
    barrier: multiprocessing.synchronize.Barrier,
    output: multiprocessing.queues.Queue,
) -> None:
    repository = ScanJobRepository(Path(data_dir))
    barrier.wait(timeout=10)
    lease = repository.acquire_target_operation(
        "target-1",
        "api-stop",
        NOW + timedelta(seconds=11),
        timedelta(seconds=30),
    )
    output.put(("direct", lease is not None))
    repository.close()


def test_create_round_trip_and_idempotency(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)

    created, was_created = repository.create(
        _job("job-1"),
        idempotency_key="request-1",
        request_fingerprint="sha256:a",
    )
    replay, replay_created = repository.create(
        _job("job-unused"),
        idempotency_key="request-1",
        request_fingerprint="sha256:a",
    )

    assert was_created is True
    assert replay_created is False
    assert replay.job_id == created.job_id
    assert repository.get("job-1") == created
    assert repository.list() == [created]
    with pytest.raises(JobConflictError, match="different scan request"):
        repository.create(
            _job("job-2"),
            idempotency_key="request-1",
            request_fingerprint="sha256:b",
        )


def test_two_repository_instances_claim_only_once_and_enforce_global_cap(tmp_path: Path) -> None:
    first = ScanJobRepository(tmp_path)
    second = ScanJobRepository(tmp_path)
    first.create(_job("job-1"))
    first.create(_job("job-2"))

    claim = first.claim_next("worker-a", NOW, timedelta(seconds=30), 1)

    assert claim is not None
    assert second.claim_next("worker-b", NOW, timedelta(seconds=30), 1) is None
    assert claim.job.attempt == 1
    assert claim.job.state == ScanJobState.RUNNING
    assert "lease" not in claim.job.model_dump_json()


def test_claims_serialize_same_target_but_allow_other_targets(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    same_first = _job_for_target("same-first", "target-a")
    same_second = _job_for_target("same-second", "target-a")
    other = _job_for_target("other", "target-b")
    same_second.created_at = NOW + timedelta(seconds=1)
    other.created_at = NOW + timedelta(seconds=2)
    repository.create(same_first)
    repository.create(same_second)
    repository.create(other)

    first = repository.claim_next("worker-a", NOW, timedelta(seconds=30), 4)
    second = repository.claim_next("worker-b", NOW, timedelta(seconds=30), 4)

    assert first is not None and first.job.job_id == "same-first"
    assert second is not None and second.job.job_id == "other"
    assert repository.claim_next("worker-c", NOW, timedelta(seconds=30), 4) is None

    completed = first.job.model_copy(deep=True)
    completed.state = ScanJobState.SUCCEEDED
    completed.updated_at = NOW + timedelta(seconds=1)
    completed.finished_at = completed.updated_at
    repository.complete(first, completed, now=completed.updated_at)
    third = repository.claim_next(
        "worker-c",
        NOW + timedelta(seconds=2),
        timedelta(seconds=30),
        4,
    )
    assert third is not None and third.job.job_id == "same-second"


def test_direct_target_operation_is_fenced_against_job_claims(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path, token_factory=lambda: "lease-secret")
    repository.create(_job("queued"))

    lease = repository.acquire_target_operation(
        "target-1",
        "api-stop",
        NOW,
        timedelta(seconds=30),
    )
    assert lease is not None
    assert repository.claim_next("worker", NOW, timedelta(seconds=30), 4) is None
    repository.release_target_operation(lease)

    claim = repository.claim_next("worker", NOW, timedelta(seconds=30), 4)
    assert claim is not None
    assert (
        repository.acquire_target_operation(
            "target-1",
            "api-stop",
            NOW,
            timedelta(seconds=30),
        )
        is None
    )


def test_expired_direct_target_operation_does_not_pin_target(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path, token_factory=lambda: "lease-secret")
    repository.create(_job("queued"))
    lease = repository.acquire_target_operation(
        "target-1",
        "crashed-api",
        NOW,
        timedelta(seconds=1),
    )
    assert lease is not None

    claim = repository.claim_next(
        "worker",
        NOW + timedelta(seconds=2),
        timedelta(seconds=30),
        4,
    )
    assert claim is not None
    with pytest.raises(LeaseLostError, match="target operation lease lost"):
        repository.release_target_operation(lease)


def test_direct_target_operation_renewal_is_fenced(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path, token_factory=lambda: "lease-secret")
    lease = repository.acquire_target_operation(
        "target-1",
        "api-stop",
        NOW,
        timedelta(seconds=10),
    )
    assert lease is not None

    renewed = repository.renew_target_operation(
        lease,
        NOW + timedelta(seconds=5),
        timedelta(seconds=30),
    )
    assert renewed.lease_expires_at == NOW + timedelta(seconds=35)
    repository.release_target_operation(renewed)

    expired = repository.acquire_target_operation(
        "target-1",
        "stale-api",
        NOW,
        timedelta(seconds=1),
    )
    assert expired is not None
    with pytest.raises(LeaseLostError, match="target operation lease lost"):
        repository.renew_target_operation(
            expired,
            NOW + timedelta(seconds=2),
            timedelta(seconds=30),
        )


def test_direct_operation_permanently_fences_an_expired_job_generation(
    tmp_path: Path,
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("expired-worker"))
    claim = repository.claim_next("worker", NOW, timedelta(seconds=1), 4)
    assert claim is not None

    direct = repository.acquire_target_operation(
        "target-1",
        "api-stop",
        NOW + timedelta(seconds=2),
        timedelta(seconds=30),
    )
    assert direct is not None

    # A regressed worker clock must not make the old token valid while the
    # direct mutation runs, nor after that mutation releases its own lease.
    with pytest.raises(LeaseLostError):
        repository.renew(claim, NOW, timedelta(seconds=30))
    repository.release_target_operation(direct)
    with pytest.raises(LeaseLostError):
        repository.renew(claim, NOW, timedelta(seconds=30))

    stale = claim.job.model_copy(deep=True)
    stale.state = ScanJobState.SUCCEEDED
    stale.updated_at = NOW
    stale.finished_at = NOW
    with pytest.raises(LeaseLostError):
        repository.complete(claim, stale, now=NOW)

    reclaimed = repository.claim_next(
        "replacement-worker",
        NOW + timedelta(seconds=3),
        timedelta(seconds=30),
        4,
    )
    assert reclaimed is not None
    assert reclaimed.job.job_id == claim.job.job_id
    assert reclaimed.lease_epoch > claim.lease_epoch


@pytest.mark.skipif(multiprocessing.get_start_method(allow_none=True) == "forkserver", reason="")
def test_job_renewal_and_direct_operation_have_one_transactional_winner(
    tmp_path: Path,
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-race"))
    claim = repository.claim_next("worker", NOW, timedelta(seconds=10), 4)
    assert claim is not None
    repository.close()

    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    output = context.Queue()
    processes = [
        context.Process(
            target=_renew_job_in_process,
            args=(str(tmp_path), claim, barrier, output),
        ),
        context.Process(
            target=_acquire_direct_operation_in_process,
            args=(str(tmp_path), barrier, output),
        ),
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    try:
        results = dict([output.get(timeout=2), output.get(timeout=2)])
    except Empty as exc:  # pragma: no cover - produces a clearer failure than a hang
        raise AssertionError("lease race child did not report a result") from exc

    assert set(results) == {"job", "direct"}
    assert sum(results.values()) == 1


@pytest.mark.skipif(multiprocessing.get_start_method(allow_none=True) == "forkserver", reason="")
def test_multiprocess_claim_has_one_winner(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-race"))
    repository.close()
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    output = context.Queue()
    processes = [
        context.Process(target=_claim_in_process, args=(str(tmp_path), barrier, output))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    try:
        results = [output.get(timeout=2), output.get(timeout=2)]
    except Empty as exc:  # pragma: no cover - produces a clearer failure than a hang
        raise AssertionError("claim child did not report a result") from exc
    assert sorted(result is not None for result in results) == [False, True]


def test_expired_lease_is_reclaimed_and_old_owner_is_fenced(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-1"))
    old = repository.claim_next("worker-old", NOW, timedelta(seconds=10), 4)
    assert old is not None
    assert (
        repository.claim_next(
            "worker-new",
            NOW + timedelta(seconds=9),
            timedelta(seconds=10),
            4,
        )
        is None
    )

    new = repository.claim_next(
        "worker-new",
        NOW + timedelta(seconds=11),
        timedelta(seconds=10),
        4,
    )

    assert new is not None
    assert new.lease_epoch == old.lease_epoch + 1
    assert new.job.attempt == 2
    stale = old.job.model_copy(deep=True)
    stale.state = ScanJobState.SUCCEEDED
    stale.updated_at = NOW + timedelta(seconds=12)
    stale.finished_at = stale.updated_at
    with pytest.raises(LeaseLostError):
        repository.complete(old, stale, now=stale.updated_at)

    finished = new.job.model_copy(deep=True)
    finished.state = ScanJobState.SUCCEEDED
    finished.updated_at = NOW + timedelta(seconds=12)
    finished.finished_at = finished.updated_at
    assert (
        repository.complete(new, finished, now=finished.updated_at).state == ScanJobState.SUCCEEDED
    )


def test_expired_job_lease_cannot_renew_or_complete_at_its_deadline(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("expired"))
    claim = repository.claim_next("worker", NOW, timedelta(seconds=10), 4)
    assert claim is not None

    deadline = NOW + timedelta(seconds=10)
    with pytest.raises(LeaseLostError):
        repository.renew(claim, deadline, timedelta(seconds=30))

    finished = claim.job.model_copy(deep=True)
    finished.state = ScanJobState.SUCCEEDED
    finished.updated_at = NOW + timedelta(seconds=9)
    finished.finished_at = finished.updated_at
    with pytest.raises(LeaseLostError):
        repository.complete(claim, finished, now=deadline)


def test_job_heartbeat_rejects_clock_regression_without_breaking_later_renewal(
    tmp_path: Path,
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("long-running"))
    claim = repository.claim_next("worker", NOW, timedelta(seconds=30), 4)
    assert claim is not None
    renewed = repository.renew(
        claim,
        NOW + timedelta(seconds=10),
        timedelta(seconds=30),
    )

    with pytest.raises(LeaseLostError):
        repository.renew(
            renewed,
            NOW + timedelta(seconds=9),
            timedelta(seconds=30),
        )

    later = repository.renew(
        renewed,
        NOW + timedelta(seconds=20),
        timedelta(seconds=30),
    )
    assert later.lease_expires_at == NOW + timedelta(seconds=50)


def test_expired_final_attempt_gets_one_capped_reconciliation_claim(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    job = _job("job-final-attempt")
    job.max_attempts = 1
    repository.create(job)
    claim = repository.claim_next("worker-old", NOW, timedelta(seconds=1), 4)
    assert claim is not None
    assert claim.job.attempt == 1

    reconciler = repository.claim_next(
        "worker-new",
        NOW + timedelta(seconds=2),
        timedelta(seconds=1),
        4,
    )

    assert reconciler is not None
    assert reconciler.job.state == ScanJobState.RUNNING
    assert reconciler.job.attempt == 2
    assert reconciler.job.attempt == reconciler.job.max_attempts + 1

    reclaimed_again = repository.claim_next(
        "worker-after-reconcile-crash",
        NOW + timedelta(seconds=4),
        timedelta(seconds=30),
        4,
    )
    assert reclaimed_again is not None
    assert reclaimed_again.job.attempt == 2


def test_expired_final_guard_attempt_gets_reconciliation_claim(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    job = _job("guard-final-attempt")
    job.capability = ScanCapability.GUARD
    job.max_attempts = 1
    repository.create(job)
    old = repository.claim_next("worker-old", NOW, timedelta(seconds=1), 4)
    assert old is not None and old.job.attempt == 1

    reconciler = repository.claim_next(
        "worker-reconcile",
        NOW + timedelta(seconds=2),
        timedelta(seconds=30),
        4,
    )

    assert reconciler is not None
    assert reconciler.job.job_id == job.job_id
    assert reconciler.job.attempt == 2
    assert reconciler.job.attempt > reconciler.job.max_attempts


def test_claim_can_exclude_a_locally_active_expired_job(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("active-local"))
    repository.create(_job("next"))
    old = repository.claim_next("worker", NOW, timedelta(seconds=1), 2)
    assert old is not None
    assert old.job.job_id == "active-local"

    claim = repository.claim_next(
        "worker",
        NOW + timedelta(seconds=2),
        timedelta(seconds=30),
        2,
        ("active-local",),
    )

    assert claim is not None
    assert claim.job.job_id == "next"
    assert repository.get("active-local").attempt == 1  # type: ignore[union-attr]


def test_retry_cancel_and_completion_races_are_fenced(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("queued"))
    cancelled = repository.request_cancel("queued", NOW + timedelta(seconds=1))
    assert cancelled.state == ScanJobState.CANCELLED
    retried = repository.manual_retry("queued", NOW + timedelta(seconds=2))
    assert retried.state == ScanJobState.PENDING
    assert retried.attempt == 0

    claim = repository.claim_next(
        "worker",
        NOW + timedelta(seconds=2),
        timedelta(seconds=30),
        4,
    )
    assert claim is not None
    cancelling = repository.request_cancel("queued", NOW + timedelta(seconds=3))
    assert cancelling.state == ScanJobState.CANCELLING
    renewed = repository.renew(
        claim,
        NOW + timedelta(seconds=4),
        timedelta(seconds=30),
    )
    assert renewed.job.state == ScanJobState.CANCELLING

    wrong = renewed.job.model_copy(deep=True)
    wrong.state = ScanJobState.SUCCEEDED
    wrong.updated_at = NOW + timedelta(seconds=5)
    wrong.finished_at = wrong.updated_at
    with pytest.raises(LeaseLostError, match="cancellation won"):
        repository.complete(renewed, wrong, now=wrong.updated_at)

    final = renewed.job.model_copy(deep=True)
    final.state = ScanJobState.CANCELLED
    final.updated_at = NOW + timedelta(seconds=5)
    final.finished_at = final.updated_at
    assert repository.complete(renewed, final, now=final.updated_at).state == ScanJobState.CANCELLED


def test_legacy_import_is_idempotent_and_fails_unknown_running_work(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    legacy = [_job("pending"), _job("running", ScanJobState.RUNNING)]

    assert repository.import_legacy(legacy, NOW + timedelta(hours=1)) == 2
    assert repository.import_legacy(legacy, NOW + timedelta(hours=1)) == 0
    assert repository.get("pending").state == ScanJobState.PENDING  # type: ignore[union-attr]
    running = repository.get("running")
    assert running is not None
    assert running.state == ScanJobState.FAILED
    assert "legacy Form stopped" in (running.error or "")


def test_capacity_never_evicts_active_heads_but_can_reclaim_terminal(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path, max_jobs=1)
    repository.create(_job("active"))
    with pytest.raises(StorageCapacityError, match="refusing to evict"):
        repository.create(_job("blocked"))

    claim = repository.claim_next("worker", NOW, timedelta(seconds=30), 1)
    assert claim is not None
    done = claim.job.model_copy(deep=True)
    done.state = ScanJobState.SUCCEEDED
    done.updated_at = NOW + timedelta(seconds=1)
    done.finished_at = done.updated_at
    repository.complete(claim, done, now=done.updated_at)

    repository.create(_job("replacement"))
    assert repository.get("active") is None
    assert repository.get("replacement") is not None


def test_capacity_can_use_one_terminal_without_reaching_low_water(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path, max_jobs=20)
    for index in range(20):
        repository.create(_job(f"job-{index:02d}"))
    claim = repository.claim_next("worker", NOW, timedelta(seconds=30), 20)
    assert claim is not None
    done = claim.job.model_copy(deep=True)
    done.state = ScanJobState.SUCCEEDED
    done.updated_at = NOW + timedelta(seconds=1)
    done.finished_at = done.updated_at
    repository.complete(claim, done, now=done.updated_at)

    repository.create(_job("replacement"))

    assert repository.get(claim.job.job_id) is None
    assert repository.get("replacement") is not None


def test_record_and_history_caps_are_enforced(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path, max_record_bytes=1_000, max_history=2)
    oversized = _job("large")
    oversized.address = "x" * 2_000
    with pytest.raises(StorageCapacityError, match="exceeds"):
        repository.create(oversized)

    repository.create(_job("normal"))
    repository.request_cancel("normal", NOW + timedelta(seconds=1))
    repository.manual_retry("normal", NOW + timedelta(seconds=2))
    history = repository.history("normal", 10)
    assert len(history) == 2
    assert history[0].state == ScanJobState.PENDING
