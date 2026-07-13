"""Durable Form worker recovery, retry, cancellation, timeout and concurrency."""

from __future__ import annotations

import asyncio
import random
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from analyzer.schemas import AssetReport

from kcatta_form.agent_identity_store import AgentIdentityRepository
from kcatta_form.agent_pki import AgentCertificateAuthority, AgentIdentityService
from kcatta_form.analyzer_client import AnalyzerUpstreamError
from kcatta_form.deploy.agent import GuardDeploymentManifest, GuardDeploymentUncertainError
from kcatta_form.job_store import ScanJobRepository
from kcatta_form.scan_artifacts import ScanArtifactStore
from kcatta_form.scan_worker import (
    ExecutionControl,
    GuardReconciliationRequired,
    ScanExecutionInterrupted,
    ScanJobWorker,
    ScanWorkerConfig,
)
from kcatta_form.schemas import (
    AgentCertificateState,
    ScanCapability,
    ScanJob,
    ScanJobState,
    ScanResult,
    ScanTarget,
)

NOW = datetime(2026, 7, 10, 8, 0, tzinfo=UTC)


def _job(job_id: str, *, max_attempts: int = 3) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.HOST,
        created_at=NOW,
        max_attempts=max_attempts,
    )


def _target() -> ScanTarget:
    return ScanTarget(
        target_id="target-1",
        name="node",
        address="root@192.0.2.10",
        created_at=NOW,
    )


def _report(report_id: str = "report-1") -> AssetReport:
    return AssetReport.model_validate(
        {
            "report_id": report_id,
            "collected_at": NOW.isoformat(),
            "scanner_version": "test",
            "host": {"host_id": "host-1", "hostname": "node", "os": "Linux"},
            "assets": [],
            "vulnerabilities": [],
        }
    )


def _guard_manifest(identity_generation: str | None, pid: str = "9876") -> GuardDeploymentManifest:
    return GuardDeploymentManifest(
        deployment_id="d" * 32,
        identity_generation=identity_generation,
        binary_sha256="a" * 64,
        config_sha256=None,
        pid=pid,
        unit_name="kcatta-guard",
        binary_path="/var/lib/agent-guard/agentd",
        config_path=None,
    )


def _guard_proof(
    manifest: GuardDeploymentManifest | None,
    *,
    alive: bool = True,
    pid: str | None = None,
):  # type: ignore[no-untyped-def]
    return SimpleNamespace(
        manifest=manifest,
        status=SimpleNamespace(
            alive=alive,
            supervisor="systemd" if alive else "unknown",
            pid=(manifest.pid if manifest is not None else None) if pid is None else pid,
            detail="active" if alive else "stopped",
        ),
    )


class _TargetStore:
    def find_one(self, field: str, value: str):
        assert field == "target_id"
        return _target().model_dump(mode="json") if value == "target-1" else None


class _Analyzer:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.reports: list[AssetReport] = []

    async def ingest_asset_report(self, report: AssetReport):
        if self.failures:
            self.failures -= 1
            raise AnalyzerUpstreamError("temporary outage", status_code=503)
        self.reports.append(report)

    async def ingest_trace_batch(self, batch):  # type: ignore[no-untyped-def]
        raise AssertionError(f"unexpected trace batch: {batch}")


def _config(**overrides: float | int) -> ScanWorkerConfig:
    values: dict[str, float | int] = {
        "concurrency": 2,
        "job_timeout_seconds": 2,
        # Production uses a 60s/15s lease/heartbeat pair. Keep tests fast while
        # leaving enough scheduler headroom that strict non-revivable leases do
        # not turn ordinary fsync/thread-pool jitter into a synthetic takeover.
        "lease_seconds": 2,
        "heartbeat_seconds": 0.1,
        "poll_seconds": 0.01,
        "max_attempts": 3,
        "retry_base_seconds": 0.01,
        "retry_max_seconds": 0.02,
        "shutdown_grace_seconds": 0.5,
    }
    values.update(overrides)
    return ScanWorkerConfig(**values)  # type: ignore[arg-type]


def _worker(
    tmp_path: Path,
    repository: ScanJobRepository,
    analyzer: _Analyzer,
    **config: float | int,
) -> ScanJobWorker:
    state = SimpleNamespace(
        scan_target_store=_TargetStore(),
        analyzer_client=analyzer,
        ingest_token="ingest-secret",
    )
    return ScanJobWorker(
        state,  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://form.example.test",
        config=_config(**config),
        worker_id="worker-test",
        random_source=random.Random(0),
    )


async def _wait_for_state(
    repository: ScanJobRepository,
    job_id: str,
    states: set[ScanJobState],
    timeout: float = 3,
) -> ScanJob:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        job = await asyncio.to_thread(repository.get, job_id)
        if job is not None and job.state in states:
            return job
        await asyncio.sleep(0.01)
    raise AssertionError(f"job {job_id} never reached {sorted(state.value for state in states)}")


def test_pending_job_is_executed_after_worker_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed = ScanJobRepository(tmp_path)
    seed.create(_job("job-restart"))
    seed.close()
    calls = 0

    def collect(target, options):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return _report()

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", collect)

    async def scenario() -> ScanJob:
        repository = ScanJobRepository(tmp_path)
        analyzer = _Analyzer()
        worker = _worker(tmp_path, repository, analyzer)
        await worker.start()
        try:
            job = await _wait_for_state(repository, "job-restart", {ScanJobState.SUCCEEDED})
            assert len(analyzer.reports) == 1
            return job
        finally:
            await worker.stop()
            repository.close()

    job = asyncio.run(scenario())
    assert job.attempt == 1
    assert calls == 1


def test_analyzer_retry_reuses_durable_artifact_without_redeploy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-forward-retry"))
    calls = 0

    def collect(target, options):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return _report("stable-report")

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", collect)

    async def scenario() -> ScanJob:
        analyzer = _Analyzer(failures=1)
        worker = _worker(tmp_path, repository, analyzer)
        await worker.start()
        try:
            job = await _wait_for_state(
                repository,
                "job-forward-retry",
                {ScanJobState.SUCCEEDED},
                timeout=15,
            )
            assert [report.report_id for report in analyzer.reports] == ["stable-report"]
            return job
        finally:
            await worker.stop()

    job = asyncio.run(scenario())
    assert job.attempt == 2
    assert calls == 1
    assert ScanArtifactStore(tmp_path / "artifacts").load("job-forward-retry") is None


def test_guard_retry_aborts_failed_certificate_and_activates_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path / "jobs")
    repository.create(
        ScanJob(
            job_id="job-guard-cert-retry",
            target_id="target-1",
            address="root@192.0.2.10",
            capability=ScanCapability.GUARD,
            created_at=NOW,
            max_attempts=2,
        )
    )
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    state = SimpleNamespace(
        scan_target_store=_TargetStore(),
        analyzer_client=_Analyzer(),
        ingest_token="legacy-must-not-be-deployed",
        agent_identity_service=identity_service,
    )
    worker = ScanJobWorker(
        state,  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://form-agent.example.test:10443",
        # PKI generation + SQLite FULL fsync is intentionally durable and can
        # exceed the tiny 300ms lease used by the fast host-worker tests on a
        # loaded CI runner.
        config=_config(
            max_attempts=2,
            job_timeout_seconds=15,
            lease_seconds=5,
            heartbeat_seconds=0.2,
        ),
        worker_id="worker-guard-cert-retry",
        random_source=random.Random(0),
    )
    bundles = []

    def deploy_guard(target, public_url, token, bundle, activation_callback):  # type: ignore[no-untyped-def]
        assert public_url == "https://form-agent.example.test:10443"
        assert token is None
        bundles.append(bundle)
        if len(bundles) == 1:
            raise OSError("SSH dropped during first certificate deployment")
        activation_callback()
        return ScanResult(kind=ScanCapability.GUARD, host_id="remote-claim", pid="4321")

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_guard", deploy_guard)
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_deployment_proof_for",
        lambda target: _guard_proof(
            _guard_manifest(
                "generation-"
                f"{bundles[-1].certificate.generation}-"
                f"{bundles[-1].certificate.cert_sha256[:16]}",
                "4321",
            )
        ),
    )
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.stop_guard_for",
        lambda target: pytest.fail(
            "a pre-commit retryable deploy failure must not stop a target-wide healthy Guard"
        ),
    )

    async def scenario() -> ScanJob:
        await worker.start()
        try:
            return await _wait_for_state(
                repository,
                "job-guard-cert-retry",
                {ScanJobState.SUCCEEDED},
                timeout=15,
            )
        finally:
            await worker.stop()

    try:
        job = asyncio.run(scenario())
        identity = identity_service.repository.get_by_target("target-1")
    finally:
        identity_service.repository.close()
        repository.close()

    assert job.attempt == 2
    assert job.result is not None
    assert job.result.host_id == "target-1"
    assert len(bundles) == 2
    assert [certificate.state for certificate in identity.certificates] == [
        AgentCertificateState.REVOKED,
        AgentCertificateState.ACTIVE,
    ]


def test_uncertain_guard_deploy_keeps_staged_generation_for_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    repository = ScanJobRepository(tmp_path / "jobs")
    state = SimpleNamespace(
        scan_target_store=_TargetStore(),
        analyzer_client=_Analyzer(),
        agent_identity_service=identity_service,
    )
    worker = ScanJobWorker(
        state,  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(),
    )
    job = ScanJob(
        job_id="job-guard-uncertain",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=NOW,
        attempt=1,
        max_attempts=1,
    )

    def uncertain(target, public_url, token, bundle, activation_callback):  # type: ignore[no-untyped-def]
        raise GuardDeploymentUncertainError(
            target=target.address,
            deployment_id="d" * 32,
            identity_generation=(
                f"generation-{bundle.certificate.generation}-{bundle.certificate.cert_sha256[:16]}"
            ),
        )

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_guard", uncertain)

    async def scenario() -> None:
        with pytest.raises(GuardDeploymentUncertainError):
            await worker._collect_and_spool(job, _target(), ExecutionControl())

    try:
        asyncio.run(scenario())
        identity = identity_service.repository.get_by_target("target-1")
    finally:
        identity_service.repository.close()
        repository.close()

    assert len(identity.certificates) == 1
    assert identity.certificates[0].state is AgentCertificateState.STAGED


def test_guard_recovery_aborts_unused_staged_generation_before_redeploy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    abandoned = identity_service.stage_for_target(
        "target-1",
        "target-1",
        ["guard-event"],
        idempotency_key="job-guard-predeploy-crash:attempt:1",
    )
    repository = ScanJobRepository(tmp_path / "jobs")
    worker = ScanJobWorker(
        SimpleNamespace(
            scan_target_store=_TargetStore(),
            analyzer_client=_Analyzer(),
            agent_identity_service=identity_service,
        ),  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(),
    )
    job = ScanJob(
        job_id="job-guard-predeploy-crash",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=NOW,
        attempt=2,
        max_attempts=3,
    )
    deployed = []

    def proof(_target):  # type: ignore[no-untyped-def]
        if not deployed:
            return _guard_proof(None, alive=False)
        bundle = deployed[-1]
        generation = (
            f"generation-{bundle.certificate.generation}-{bundle.certificate.cert_sha256[:16]}"
        )
        return _guard_proof(_guard_manifest(generation, "2468"))

    def deploy(_target, _url, token, bundle, activation_callback):  # type: ignore[no-untyped-def]
        assert token is None
        deployed.append(bundle)
        activation_callback()
        return ScanResult(kind=ScanCapability.GUARD, host_id="remote", pid="2468")

    monkeypatch.setattr("kcatta_form.deploy.trigger.guard_deployment_proof_for", proof)
    monkeypatch.setattr("kcatta_form.deploy.trigger.run_guard", deploy)

    try:
        _metadata, result = asyncio.run(
            worker._collect_and_spool(job, _target(), ExecutionControl())
        )
        identity = identity_service.repository.get_by_target("target-1")
    finally:
        identity_service.repository.close()
        repository.close()

    assert result.pid == "2468"
    assert len(deployed) == 1
    assert deployed[0].certificate.generation != abandoned.certificate.generation
    assert [certificate.state for certificate in identity.certificates] == [
        AgentCertificateState.REVOKED,
        AgentCertificateState.ACTIVE,
    ]


def test_final_guard_reconciliation_keeps_identity_read_failure_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    identity_service.ensure_identity("target-1", "target-1", ["guard-event"])
    repository = ScanJobRepository(tmp_path / "jobs")
    worker = ScanJobWorker(
        SimpleNamespace(
            scan_target_store=_TargetStore(),
            analyzer_client=_Analyzer(),
            agent_identity_service=identity_service,
        ),  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(),
    )
    monkeypatch.setattr(
        identity_service.repository,
        "get_by_idempotency_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("identity DB busy")),
    )
    job = ScanJob(
        job_id="job-guard-identity-read",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=NOW,
        attempt=2,
        max_attempts=1,
    )

    try:
        with pytest.raises(GuardReconciliationRequired, match="job-owned"):
            asyncio.run(
                worker._reconcile_guard_deployment(
                    job,
                    _target(),
                    ExecutionControl(),
                    include_current_attempt=True,
                    activate_staged=True,
                )
            )
    finally:
        identity_service.repository.close()
        repository.close()


def test_final_guard_reconciliation_keeps_activation_failure_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    staged = identity_service.stage_for_target(
        "target-1",
        "target-1",
        ["guard-event"],
        idempotency_key="job-guard-activation:attempt:1",
    )
    generation = f"generation-{staged.certificate.generation}-{staged.certificate.cert_sha256[:16]}"
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_deployment_proof_for",
        lambda _target: _guard_proof(_guard_manifest(generation)),
    )
    monkeypatch.setattr(
        identity_service,
        "activate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("identity DB busy")),
    )
    repository = ScanJobRepository(tmp_path / "jobs")
    worker = ScanJobWorker(
        SimpleNamespace(
            scan_target_store=_TargetStore(),
            analyzer_client=_Analyzer(),
            agent_identity_service=identity_service,
        ),  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(),
    )
    job = ScanJob(
        job_id="job-guard-activation",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=NOW,
        attempt=2,
        max_attempts=1,
    )

    try:
        with pytest.raises(GuardReconciliationRequired, match="activate"):
            asyncio.run(
                worker._reconcile_guard_deployment(
                    job,
                    _target(),
                    ExecutionControl(),
                    include_current_attempt=True,
                    activate_staged=True,
                )
            )
    finally:
        identity_service.repository.close()
        repository.close()


def test_final_guard_artifact_failure_retries_revoked_generation_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    repository = ScanJobRepository(tmp_path / "jobs")
    artifacts = ScanArtifactStore(tmp_path / "artifacts")
    state = SimpleNamespace(
        scan_target_store=_TargetStore(),
        analyzer_client=_Analyzer(),
        agent_identity_service=identity_service,
    )
    worker = ScanJobWorker(
        state,  # type: ignore[arg-type]
        repository,
        artifacts,
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(),
    )
    job = ScanJob(
        job_id="job-guard-final-spool",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=NOW,
        attempt=1,
        max_attempts=1,
    )
    bundles = []

    def deploy(target, public_url, token, bundle, activation_callback):  # type: ignore[no-untyped-def]
        bundles.append(bundle)
        activation_callback()
        return ScanResult(kind=ScanCapability.GUARD, host_id="remote", pid="9876")

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_guard", deploy)
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_deployment_proof_for",
        lambda target: _guard_proof(
            _guard_manifest(
                f"generation-{bundles[-1].certificate.generation}-"
                f"{bundles[-1].certificate.cert_sha256[:16]}"
            )
        ),
    )
    stopped: list[GuardDeploymentManifest] = []

    def stop(_target, *, expected_manifest):  # type: ignore[no-untyped-def]
        stopped.append(expected_manifest)
        if len(stopped) == 1:
            raise OSError("first conditional stop lost its response")
        return SimpleNamespace(alive=False, pid=None, detail="stopped")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", stop)
    monkeypatch.setattr(
        artifacts, "save", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("spool full"))
    )

    async def scenario() -> None:
        with pytest.raises(GuardReconciliationRequired, match="compensation is pending"):
            await worker._collect_and_spool(job, _target(), ExecutionControl())
        reconciliation = job.model_copy(update={"attempt": 2})
        with pytest.raises(ValueError, match="conditionally torn down"):
            await worker._collect_and_spool(
                reconciliation,
                _target(),
                ExecutionControl(),
            )

    try:
        asyncio.run(scenario())
        identity = identity_service.repository.get_by_target("target-1")
    finally:
        identity_service.repository.close()
        repository.close()

    assert identity.certificates[0].state is AgentCertificateState.REVOKED
    assert len(stopped) == 2
    assert stopped[0] == stopped[1]


@pytest.mark.parametrize("initial_state", ["staged", "active"])
def test_guard_recovery_requires_manifest_and_live_pid_after_worker_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_state: str,
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    staged = identity_service.stage_for_target(
        "target-1",
        "target-1",
        ["guard-event"],
        idempotency_key="job-guard-recover:attempt:1",
    )
    expected_remote = (
        f"generation-{staged.certificate.generation}-{staged.certificate.cert_sha256[:16]}"
    )
    if initial_state == "active":
        identity_service.activate(staged.identity.agent_id, staged.certificate.generation)
    state = SimpleNamespace(
        scan_target_store=_TargetStore(),
        analyzer_client=_Analyzer(),
        ingest_token=None,
        agent_identity_service=identity_service,
    )
    repository = ScanJobRepository(tmp_path / "jobs")
    worker = ScanJobWorker(
        state,  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(job_timeout_seconds=15, lease_seconds=5, heartbeat_seconds=0.2),
        worker_id="worker-guard-recovery",
    )
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_deployment_proof_for",
        lambda target: _guard_proof(_guard_manifest(expected_remote)),
    )
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.run_guard",
        lambda *_args, **_kwargs: pytest.fail("recovery must not redeploy the private key"),
    )
    job = ScanJob(
        job_id="job-guard-recover",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=NOW,
        attempt=2,
        max_attempts=1,
    )

    control = ExecutionControl()

    async def scenario():  # type: ignore[no-untyped-def]
        return await worker._collect_and_spool(job, _target(), control)

    try:
        _metadata, result = asyncio.run(scenario())
        identity = identity_service.repository.get_by_target("target-1")
    finally:
        identity_service.repository.close()
        repository.close()

    assert isinstance(result, ScanResult)
    assert result.pid == "9876"
    assert control.guard_side_effect_committed is True
    assert identity.certificates[0].state is AgentCertificateState.ACTIVE


def test_mtls_recovery_accepts_proven_systemd_pid_rollover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    staged = identity_service.stage_for_target(
        "target-1",
        "target-1",
        ["guard-event"],
        idempotency_key="job-guard-pid-rollover:attempt:1",
    )
    identity_service.activate(staged.identity.agent_id, staged.certificate.generation)
    expected_generation = (
        f"generation-{staged.certificate.generation}-{staged.certificate.cert_sha256[:16]}"
    )
    refreshed_manifest = _guard_manifest(expected_generation, "2222")
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_deployment_proof_for",
        lambda target: _guard_proof(refreshed_manifest),
    )
    repository = ScanJobRepository(tmp_path / "jobs")
    artifacts = ScanArtifactStore(tmp_path / "artifacts")
    artifacts.save(
        "job-guard-pid-rollover",
        "scan-result",
        ScanResult(kind=ScanCapability.GUARD, host_id="target-1", pid="1111"),
    )
    worker = ScanJobWorker(
        SimpleNamespace(
            scan_target_store=_TargetStore(),
            analyzer_client=_Analyzer(),
            agent_identity_service=identity_service,
        ),  # type: ignore[arg-type]
        repository,
        artifacts,
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(),
    )
    job = ScanJob(
        job_id="job-guard-pid-rollover",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=NOW,
        attempt=2,
        max_attempts=1,
    )

    try:
        result = asyncio.run(worker._execute(job, ExecutionControl()))
    finally:
        identity_service.repository.close()
        repository.close()

    assert result.pid == "2222"


@pytest.mark.parametrize("mismatch", [None, "identity", "pid"])
def test_crash_reclaimed_cancelling_guard_uses_exact_manifest_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str | None,
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    staged = identity_service.stage_for_target(
        "target-1",
        "target-1",
        ["guard-event"],
        idempotency_key="job-guard-cancelling:attempt:1",
    )
    expected_generation = (
        f"generation-{staged.certificate.generation}-{staged.certificate.cert_sha256[:16]}"
    )
    manifest = _guard_manifest(
        expected_generation if mismatch != "identity" else "generation-999-0123456789abcdef"
    )
    stopped: list[GuardDeploymentManifest] = []
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_deployment_proof_for",
        lambda target: _guard_proof(manifest, pid="9999" if mismatch == "pid" else None),
    )

    def stop(_target, *, expected_manifest):  # type: ignore[no-untyped-def]
        stopped.append(expected_manifest)
        return SimpleNamespace(alive=False, pid=None, detail="stopped")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", stop)
    repository = ScanJobRepository(tmp_path / "jobs")
    state = SimpleNamespace(
        scan_target_store=_TargetStore(),
        analyzer_client=_Analyzer(),
        agent_identity_service=identity_service,
    )
    worker = ScanJobWorker(
        state,  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(),
    )
    job = ScanJob(
        job_id="job-guard-cancelling",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        state=ScanJobState.CANCELLING,
        created_at=NOW,
        attempt=1,
        max_attempts=1,
    )
    control = ExecutionControl()
    control.cancel_requested.set()

    async def scenario() -> None:
        expected = ScanExecutionInterrupted if mismatch is None else GuardReconciliationRequired
        with pytest.raises(expected):
            await worker._execute(job, control)

    try:
        asyncio.run(scenario())
        certificate = identity_service.repository.get_certificate(
            staged.identity.agent_id,
            staged.certificate.generation,
        )
    finally:
        identity_service.repository.close()
        repository.close()

    if mismatch is None:
        assert certificate.state is AgentCertificateState.REVOKED
        assert stopped == [manifest]
    else:
        assert certificate.state is AgentCertificateState.STAGED
        assert stopped == []


def test_legacy_guard_cancel_requires_artifact_manifest_and_live_pid_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path / "jobs")
    artifacts = ScanArtifactStore(tmp_path / "artifacts")
    artifacts.save(
        "job-legacy-guard-cancel",
        "scan-result",
        ScanResult(kind=ScanCapability.GUARD, host_id="target-1", pid="9876"),
    )
    manifest = _guard_manifest(None, "9876")
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_deployment_proof_for",
        lambda target: _guard_proof(manifest),
    )
    stopped: list[GuardDeploymentManifest] = []

    def stop(_target, *, expected_manifest):  # type: ignore[no-untyped-def]
        stopped.append(expected_manifest)
        return SimpleNamespace(alive=False, pid=None, detail="stopped")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", stop)
    worker = _worker(tmp_path, repository, _Analyzer())
    job = ScanJob(
        job_id="job-legacy-guard-cancel",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        state=ScanJobState.CANCELLING,
        created_at=NOW,
        attempt=1,
        max_attempts=1,
    )
    control = ExecutionControl()
    control.cancel_requested.set()

    async def scenario() -> None:
        with pytest.raises(ScanExecutionInterrupted, match="compensated"):
            await worker._execute(job, control)

    try:
        asyncio.run(scenario())
    finally:
        repository.close()

    assert stopped == [manifest]


def test_fresh_legacy_guard_cancel_binds_proof_before_spool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path / "jobs")
    worker = _worker(tmp_path, repository, _Analyzer())
    manifest = _guard_manifest(None, "9876")
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.run_guard",
        lambda *_args, **_kwargs: ScanResult(
            kind=ScanCapability.GUARD,
            host_id="target-1",
            pid="9876",
        ),
    )
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_deployment_proof_for",
        lambda target: _guard_proof(manifest),
    )
    stopped: list[GuardDeploymentManifest] = []

    def stop(_target, *, expected_manifest):  # type: ignore[no-untyped-def]
        stopped.append(expected_manifest)
        return SimpleNamespace(alive=False, pid=None, detail="stopped")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", stop)
    job = ScanJob(
        job_id="job-fresh-legacy-cancel",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=NOW,
        attempt=1,
        max_attempts=1,
    )
    control = ExecutionControl()
    # Model cancellation racing after the pre-collection check while the
    # blocking deployment is in flight.
    control.cancel_requested.set()

    async def scenario() -> None:
        with pytest.raises(ScanExecutionInterrupted, match="compensated"):
            await worker._collect_and_spool(job, _target(), control)

    try:
        asyncio.run(scenario())
    finally:
        repository.close()

    assert stopped == [manifest]
    assert worker.artifacts.load(job.job_id) is None


def test_crash_reclaimed_guard_compensation_keeps_lease_heartbeating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    staged = identity_service.stage_for_target(
        "target-1",
        "target-1",
        ["guard-event"],
        idempotency_key="job-guard-heartbeat:attempt:1",
    )
    expected_generation = (
        f"generation-{staged.certificate.generation}-{staged.certificate.cert_sha256[:16]}"
    )
    manifest = _guard_manifest(expected_generation)
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.guard_deployment_proof_for",
        lambda target: _guard_proof(manifest),
    )
    entered = threading.Event()
    release = threading.Event()

    def stop(_target, *, expected_manifest):  # type: ignore[no-untyped-def]
        assert expected_manifest is manifest
        entered.set()
        assert release.wait(timeout=3)
        return SimpleNamespace(alive=False, pid=None, detail="stopped")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", stop)
    repository = ScanJobRepository(tmp_path / "jobs")
    job = ScanJob(
        job_id="job-guard-heartbeat",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=datetime.now(UTC),
        max_attempts=1,
    )
    repository.create(job)
    old_claim = repository.claim_next(
        "dead-worker",
        datetime.now(UTC),
        timedelta(seconds=0.1),
        1,
    )
    assert old_claim is not None
    cancelling = repository.request_cancel(job.job_id, datetime.now(UTC))
    assert cancelling.state is ScanJobState.CANCELLING
    state = SimpleNamespace(
        scan_target_store=_TargetStore(),
        analyzer_client=_Analyzer(),
        agent_identity_service=identity_service,
    )
    worker = ScanJobWorker(
        state,  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(
            job_timeout_seconds=5,
            lease_seconds=1,
            heartbeat_seconds=0.05,
        ),
        worker_id="guard-heartbeat-reconciler",
    )

    async def scenario() -> ScanJob:
        await worker.start()
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            # Stay blocked longer than one full lease. A healthy worker must
            # retain ownership through heartbeats, without relying on the old
            # (unsafe) ability to revive an already-expired lease.
            await asyncio.sleep(1.3)
            still_owned = repository.get(job.job_id)
            assert still_owned is not None
            assert still_owned.state is ScanJobState.CANCELLING
            release.set()
            return await _wait_for_state(
                repository,
                job.job_id,
                {ScanJobState.CANCELLED},
            )
        finally:
            release.set()
            await worker.stop()

    try:
        cancelled = asyncio.run(scenario())
        certificate = identity_service.repository.get_certificate(
            staged.identity.agent_id,
            staged.certificate.generation,
        )
    finally:
        identity_service.repository.close()
        repository.close()

    assert cancelled.state is ScanJobState.CANCELLED
    assert certificate.state is AgentCertificateState.REVOKED


def test_guard_completion_cancel_race_compensates_under_same_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = AgentCertificateAuthority.initialize(
        tmp_path / "credentials" / "agent-ca.pem",
        tmp_path / "credentials" / "agent-ca-key.pem",
    )
    identity_service = AgentIdentityService(
        AgentIdentityRepository(tmp_path / "agent-identities"),
        authority,
    )
    staged = identity_service.stage_for_target(
        "target-1",
        "target-1",
        ["guard-event"],
        idempotency_key="job-guard-complete-race:attempt:1",
    )
    identity_service.activate(staged.identity.agent_id, staged.certificate.generation)
    expected_generation = (
        f"generation-{staged.certificate.generation}-{staged.certificate.cert_sha256[:16]}"
    )
    manifest = _guard_manifest(expected_generation)

    def stop(_target, *, expected_manifest):  # type: ignore[no-untyped-def]
        assert expected_manifest is manifest
        threading.Event().wait(0.35)
        return SimpleNamespace(alive=False, pid=None, detail="stopped")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", stop)
    repository = ScanJobRepository(tmp_path / "jobs")
    job = ScanJob(
        job_id="job-guard-complete-race",
        target_id="target-1",
        address="root@192.0.2.10",
        capability=ScanCapability.GUARD,
        created_at=datetime.now(UTC),
        max_attempts=1,
    )
    repository.create(job)
    claim = repository.claim_next(
        "race-worker",
        datetime.now(UTC),
        timedelta(seconds=2),
        1,
    )
    assert claim is not None
    original_complete = repository.complete
    raced = False

    def complete_with_cancel(current_claim, updated_job):  # type: ignore[no-untyped-def]
        nonlocal raced
        if not raced:
            raced = True
            repository.request_cancel(job.job_id, datetime.now(UTC))
        return original_complete(current_claim, updated_job)

    monkeypatch.setattr(repository, "complete", complete_with_cancel)
    state = SimpleNamespace(
        scan_target_store=_TargetStore(),
        analyzer_client=_Analyzer(),
        agent_identity_service=identity_service,
    )
    worker = ScanJobWorker(
        state,  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(lease_seconds=1, heartbeat_seconds=0.05),
    )
    control = ExecutionControl(
        guard_side_effect_committed=True,
        guard_agent_id=staged.identity.agent_id,
        guard_generation=staged.certificate.generation,
        guard_deployment_manifest=manifest,
    )

    async def scenario() -> None:
        execution = asyncio.create_task(
            asyncio.sleep(
                0,
                result=ScanResult(
                    kind=ScanCapability.GUARD,
                    host_id="target-1",
                    pid="9876",
                ),
            )
        )
        await worker._finish_claim(claim, control, execution)

    try:
        asyncio.run(scenario())
        cancelled = repository.get(job.job_id)
        certificate = identity_service.repository.get_certificate(
            staged.identity.agent_id,
            staged.certificate.generation,
        )
    finally:
        identity_service.repository.close()
        repository.close()

    assert raced is True
    assert cancelled is not None and cancelled.state is ScanJobState.CANCELLED
    assert certificate.state is AgentCertificateState.REVOKED


def test_committed_guard_cleanup_revokes_before_unreachable_remote_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []

    class IdentityService:
        def revoke(self, agent_id: str, *, generation: int) -> None:
            assert agent_id == "agent-1"
            assert generation == 7
            events.append("revoke")

    manifest = _guard_manifest("generation-7-0123456789abcdef")

    def unreachable(_target, *, expected_manifest):  # type: ignore[no-untyped-def]
        assert expected_manifest is manifest
        assert events == ["revoke"]
        events.append("stop")
        raise OSError("ssh unreachable")

    monkeypatch.setattr("kcatta_form.deploy.trigger.stop_guard_for", unreachable)
    repository = ScanJobRepository(tmp_path / "jobs")
    state = SimpleNamespace(
        scan_target_store=_TargetStore(),
        analyzer_client=_Analyzer(),
        agent_identity_service=IdentityService(),
    )
    worker = ScanJobWorker(
        state,  # type: ignore[arg-type]
        repository,
        ScanArtifactStore(tmp_path / "artifacts"),
        public_url_resolver=lambda _agent_identity=False: "https://agents.example.test:10443",
        config=_config(),
    )
    job = _job("cancelled-guard")
    job.capability = ScanCapability.GUARD
    control = ExecutionControl(
        guard_side_effect_committed=True,
        guard_agent_id="agent-1",
        guard_generation=7,
        guard_deployment_manifest=manifest,
    )

    try:
        error = asyncio.run(worker._compensate_guard_if_needed(job, control))
    finally:
        repository.close()

    assert events == ["revoke", "stop"]
    assert error is not None and "ssh unreachable" in error


def test_running_cancel_waits_for_real_execution_then_finishes_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-cancel"))
    entered = threading.Event()
    release = threading.Event()

    def collect(target, options):  # type: ignore[no-untyped-def]
        entered.set()
        assert release.wait(timeout=3)
        return _report()

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", collect)

    async def scenario() -> ScanJob:
        analyzer = _Analyzer()
        worker = _worker(tmp_path, repository, analyzer)
        await worker.start()
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            cancelling = await asyncio.to_thread(
                repository.request_cancel,
                "job-cancel",
                datetime.now(UTC),
            )
            worker.notify()
            assert cancelling.state == ScanJobState.CANCELLING
            await asyncio.sleep(0.08)
            assert worker.active_count == 1
            assert repository.get("job-cancel").state == ScanJobState.CANCELLING  # type: ignore[union-attr]
            release.set()
            job = await _wait_for_state(repository, "job-cancel", {ScanJobState.CANCELLED})
            assert analyzer.reports == []
            return job
        finally:
            release.set()
            await worker.stop()

    job = asyncio.run(scenario())
    assert job.finished_at is not None


def test_timeout_does_not_release_concurrency_slot_while_thread_is_alive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-timeout", max_attempts=1))
    entered = threading.Event()
    release = threading.Event()

    def collect(target, options):  # type: ignore[no-untyped-def]
        entered.set()
        assert release.wait(timeout=3)
        return _report()

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", collect)

    async def scenario() -> ScanJob:
        worker = _worker(
            tmp_path,
            repository,
            _Analyzer(),
            concurrency=1,
            job_timeout_seconds=0.05,
        )
        await worker.start()
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            await asyncio.sleep(0.12)
            assert worker.active_count == 1
            assert repository.get("job-timeout").state == ScanJobState.RUNNING  # type: ignore[union-attr]
            release.set()
            return await _wait_for_state(repository, "job-timeout", {ScanJobState.FAILED})
        finally:
            release.set()
            await worker.stop()

    job = asyncio.run(scenario())
    assert "execution timeout" in (job.error or "")


def test_permanent_validation_error_does_not_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-permanent"))

    def invalid(target, options):  # type: ignore[no-untyped-def]
        raise ValueError("invalid target configuration")

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", invalid)

    async def scenario() -> ScanJob:
        worker = _worker(tmp_path, repository, _Analyzer())
        await worker.start()
        try:
            return await _wait_for_state(repository, "job-permanent", {ScanJobState.FAILED})
        finally:
            await worker.stop()

    job = asyncio.run(scenario())
    assert job.attempt == 1
    assert "invalid target" in (job.error or "")


def test_final_analyzer_rejection_deletes_terminal_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-terminal-artifact"))

    class RejectingAnalyzer(_Analyzer):
        async def ingest_asset_report(self, report: AssetReport):
            raise AnalyzerUpstreamError("invalid report", status_code=400)

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", lambda target, options: _report())

    async def scenario() -> ScanJob:
        worker = _worker(tmp_path, repository, RejectingAnalyzer())
        await worker.start()
        try:
            return await _wait_for_state(
                repository,
                "job-terminal-artifact",
                {ScanJobState.FAILED},
            )
        finally:
            await worker.stop()

    job = asyncio.run(scenario())
    assert job.attempt == 1
    assert ScanArtifactStore(tmp_path / "artifacts").load(job.job_id) is None


def test_analyzer_ack_wins_cancel_race_and_preserves_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-ack-race"))
    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", lambda target, options: _report())

    async def scenario() -> ScanJob:
        entered = asyncio.Event()
        release = asyncio.Event()

        class BlockingAnalyzer(_Analyzer):
            async def ingest_asset_report(self, report: AssetReport):
                entered.set()
                await release.wait()
                self.reports.append(report)

        analyzer = BlockingAnalyzer()
        worker = _worker(tmp_path, repository, analyzer)
        await worker.start()
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            cancelling = await asyncio.to_thread(
                repository.request_cancel,
                "job-ack-race",
                datetime.now(UTC),
            )
            assert cancelling.state == ScanJobState.CANCELLING
            worker.notify_cancel("job-ack-race")
            release.set()
            job = await _wait_for_state(
                repository,
                "job-ack-race",
                {ScanJobState.SUCCEEDED},
            )
            assert len(analyzer.reports) == 1
            return job
        finally:
            release.set()
            await worker.stop()

    job = asyncio.run(scenario())
    assert job.result is not None
    assert job.result.report_id == "report-1"


def test_analyzer_ack_after_deadline_preserves_existing_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-late-ack"))
    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", lambda target, options: _report())

    async def scenario() -> ScanJob:
        entered = asyncio.Event()
        release = asyncio.Event()

        class SlowAnalyzer(_Analyzer):
            async def ingest_asset_report(self, report: AssetReport):
                entered.set()
                await release.wait()
                self.reports.append(report)

        analyzer = SlowAnalyzer()
        worker = _worker(
            tmp_path,
            repository,
            analyzer,
            # Leave enough time for the durable artifact fsync on a loaded CI
            # host, then cross the deadline while Analyzer is deliberately
            # blocked below.
            job_timeout_seconds=0.5,
        )
        await worker.start()
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            await asyncio.sleep(0.65)
            release.set()
            job = await _wait_for_state(
                repository,
                "job-late-ack",
                {ScanJobState.SUCCEEDED},
            )
            assert len(analyzer.reports) == 1
            return job
        finally:
            release.set()
            await worker.stop()

    job = asyncio.run(scenario())
    assert job.result is not None
    assert job.result.report_id == "report-1"


def test_expired_last_attempt_artifact_is_reconciled_without_restart(tmp_path: Path) -> None:
    repository = ScanJobRepository(tmp_path)
    job = _job("job-expired-artifact", max_attempts=1)
    repository.create(job)
    old = repository.claim_next(
        "dead-worker",
        NOW,
        timedelta(seconds=1),
        2,
    )
    assert old is not None
    artifacts = ScanArtifactStore(tmp_path / "artifacts")
    artifacts.save(job.job_id, "asset-report", _report())

    async def scenario() -> ScanJob:
        analyzer = _Analyzer()
        worker = _worker(tmp_path, repository, analyzer)
        await worker.start()
        try:
            reconciled = await _wait_for_state(
                repository,
                job.job_id,
                {ScanJobState.SUCCEEDED},
            )
            assert [report.report_id for report in analyzer.reports] == ["report-1"]
            return reconciled
        finally:
            await worker.stop()

    reconciled = asyncio.run(scenario())
    assert reconciled.attempt == 2
    assert artifacts.load(job.job_id) is None


def test_reconciliation_claim_never_recollects_without_a_durable_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path / "jobs")
    worker = _worker(tmp_path, repository, _Analyzer())
    job = _job("job-no-final-artifact", max_attempts=1)
    job.attempt = 2
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.run_host",
        lambda *_args, **_kwargs: pytest.fail("reconciliation must not recollect"),
    )

    async def scenario() -> None:
        with pytest.raises(ValueError, match="without a durable artifact"):
            await worker._execute(job, ExecutionControl())

    try:
        asyncio.run(scenario())
    finally:
        repository.close()


def test_reconciliation_claim_forwards_existing_artifact_without_recollect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path / "jobs")
    analyzer = _Analyzer()
    worker = _worker(tmp_path, repository, analyzer)
    job = _job("job-final-artifact-forward", max_attempts=1)
    job.attempt = 2
    worker.artifacts.save(job.job_id, "asset-report", _report("durable-final"))
    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.run_host",
        lambda *_args, **_kwargs: pytest.fail("durable artifact must be reused"),
    )

    try:
        result = asyncio.run(worker._execute(job, ExecutionControl()))
    finally:
        repository.close()

    assert result.report_id == "durable-final"
    assert [report.report_id for report in analyzer.reports] == ["durable-final"]


def test_final_attempt_shutdown_leaves_running_for_durable_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path / "jobs")
    job = _job("job-final-shutdown-handoff", max_attempts=1)
    job.created_at = datetime.now(UTC)
    repository.create(job)
    claim = repository.claim_next(
        "stopping-worker",
        datetime.now(UTC),
        timedelta(seconds=0.1),
        1,
    )
    assert claim is not None and claim.job.attempt == 1
    artifacts = ScanArtifactStore(tmp_path / "artifacts")
    artifacts.save(job.job_id, "asset-report", _report("shutdown-durable"))
    stopping_worker = ScanJobWorker(
        SimpleNamespace(scan_target_store=_TargetStore(), analyzer_client=_Analyzer()),  # type: ignore[arg-type]
        repository,
        artifacts,
        public_url_resolver=lambda _agent_identity=False: "https://form.example.test",
        config=_config(lease_seconds=0.1, heartbeat_seconds=0.02),
    )
    control = ExecutionControl()
    control.shutting_down.set()

    async def leave_running() -> None:
        async def interrupted() -> ScanResult:
            raise ScanExecutionInterrupted("application lifespan stopped")

        execution = asyncio.create_task(interrupted())
        await stopping_worker._finish_claim(claim, control, execution)

    asyncio.run(leave_running())
    head = repository.get(job.job_id)
    assert head is not None and head.state is ScanJobState.RUNNING
    assert artifacts.load(job.job_id) is not None

    monkeypatch.setattr(
        "kcatta_form.deploy.trigger.run_host",
        lambda *_args, **_kwargs: pytest.fail("shutdown reconciliation must not recollect"),
    )

    async def reconcile() -> tuple[ScanJob, list[AssetReport]]:
        analyzer = _Analyzer()
        worker = _worker(
            tmp_path,
            repository,
            analyzer,
            lease_seconds=1,
            heartbeat_seconds=0.05,
        )
        await worker.start()
        try:
            reconciled = await _wait_for_state(
                repository,
                job.job_id,
                {ScanJobState.SUCCEEDED},
                timeout=5,
            )
            return reconciled, analyzer.reports
        finally:
            await worker.stop()

    try:
        reconciled, reports = asyncio.run(reconcile())
    finally:
        repository.close()

    assert reconciled.attempt == 2
    assert [report.report_id for report in reports] == ["shutdown-durable"]


def test_forced_shutdown_reaps_execution_before_dependencies_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-forced-shutdown"))
    entered = threading.Event()
    release = threading.Event()

    def collect(target, options):  # type: ignore[no-untyped-def]
        entered.set()
        assert release.wait(timeout=3)
        return _report()

    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", collect)

    async def scenario() -> tuple[int, list[AssetReport]]:
        analyzer = _Analyzer()
        worker = _worker(
            tmp_path,
            repository,
            analyzer,
            shutdown_grace_seconds=0.02,
        )
        await worker.start()
        assert await asyncio.to_thread(entered.wait, 5)
        await worker.stop()
        active_after_stop = worker.active_count
        release.set()
        await asyncio.sleep(0.1)
        return active_after_stop, analyzer.reports

    try:
        active, reports = asyncio.run(scenario())
    finally:
        release.set()
    assert active == 0
    assert reports == []
    assert ScanArtifactStore(tmp_path / "artifacts").load("job-forced-shutdown") is None


def test_worker_config_env_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORM_MAX_CONCURRENT_SCANS", "7")
    monkeypatch.setenv("FORM_SCAN_MAX_ATTEMPTS", "99")
    monkeypatch.setenv("FORM_SCAN_LEASE_SECONDS", "12")
    monkeypatch.setenv("FORM_SCAN_HEARTBEAT_SECONDS", "3")
    config = ScanWorkerConfig.from_env()
    assert config.concurrency == 7
    assert config.max_attempts == 20
    assert config.lease_seconds == 12
    assert config.heartbeat_seconds == 3


def test_poll_loop_recovers_after_transient_repository_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = ScanJobRepository(tmp_path)
    repository.create(_job("job-poll-recovery"))
    original_claim = repository.claim_next
    calls = 0

    def flaky_claim(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("temporary sqlite outage")
        return original_claim(*args, **kwargs)

    monkeypatch.setattr(repository, "claim_next", flaky_claim)
    monkeypatch.setattr("kcatta_form.deploy.trigger.run_host", lambda target, options: _report())

    async def scenario() -> ScanJob:
        worker = _worker(tmp_path, repository, _Analyzer())
        await worker.start()
        try:
            return await _wait_for_state(
                repository,
                "job-poll-recovery",
                {ScanJobState.SUCCEEDED},
            )
        finally:
            await worker.stop()

    job = asyncio.run(scenario())
    assert job.state == ScanJobState.SUCCEEDED
    assert calls >= 2
