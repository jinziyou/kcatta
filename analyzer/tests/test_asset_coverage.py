"""Fail-closed collection coverage for consecutive asset baselines."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import analyzer.api.ingest as ingest_api
from analyzer.api.alerts import _active_alert_rows
from analyzer.api.ingest import (
    _coverage_is_baseline_safe,
    _current_asset_snapshot,
    _next_asset_snapshot,
    _previous_asset_baseline,
    _snapshot_is_baseline_safe,
    store_asset_report,
)
from analyzer.schemas import (
    Alert,
    AssetReport,
    CollectionKind,
    CollectionRun,
    CollectionRunStatus,
    DetectionResult,
    DetectionStatus,
    HostInfo,
    NetworkService,
    PersistenceEntry,
    PersistenceType,
)
from analyzer.storage import JsonlStore, SqliteStore

NOW = datetime(2026, 8, 3, tzinfo=UTC)
REQUIRED = (
    CollectionKind.NETWORK_SERVICE,
    CollectionKind.DATABASE,
    CollectionKind.MESSAGE_QUEUE,
    CollectionKind.CACHE,
    CollectionKind.SECURITY_CONTROL,
    CollectionKind.SENSITIVE_FILE,
    CollectionKind.PERSISTENCE_ENTRY,
)


def _report(runs: list[CollectionRun] | None) -> AssetReport:
    return AssetReport(
        report_id="report-coverage",
        collected_at=NOW,
        scanner_version="test",
        host=HostInfo(host_id="host-1", hostname="node-1", os="Linux"),
        collection_runs=runs,
    )


def _complete_required() -> list[CollectionRun]:
    return [
        CollectionRun(collector=collector, status=CollectionRunStatus.COMPLETE)
        for collector in REQUIRED
    ]


def _network_service(index: int) -> NetworkService:
    return NetworkService(
        asset_id=f"listener-{index}",
        proto="tcp",
        port=8000 + index,
        listen_addr="0.0.0.0",
        port_asset_id=f"port-{index}",
    )


def _snapshot_report(
    report_id: str,
    *,
    collected_at: datetime = NOW,
    assets: list[NetworkService] | None = None,
    declared_network_services: int = 0,
) -> AssetReport:
    runs = _complete_required()
    runs[0] = runs[0].model_copy(update={"record_count": declared_network_services})
    return AssetReport(
        report_id=report_id,
        collected_at=collected_at,
        scanner_version="test",
        host=HostInfo(host_id="host-1", hostname="node-1", os="Linux"),
        assets=assets or [],
        collection_runs=runs,
    )


@pytest.mark.parametrize("runs", [None, []])
def test_empty_or_missing_collection_coverage_is_not_baseline_safe(
    runs: list[CollectionRun] | None,
) -> None:
    assert not _coverage_is_baseline_safe(_report(runs))


def test_missing_required_collection_is_not_baseline_safe() -> None:
    assert not _coverage_is_baseline_safe(_report(_complete_required()[:-1]))


@pytest.mark.parametrize(
    "status,reason",
    [
        (CollectionRunStatus.DISABLED, "collector_disabled"),
        (CollectionRunStatus.PARTIAL, "collector_limit_reached"),
        (CollectionRunStatus.FAILED, "collector_source_unavailable"),
    ],
)
def test_noncomplete_required_collection_is_not_baseline_safe(
    status: CollectionRunStatus,
    reason: str,
) -> None:
    runs = _complete_required()
    runs[0] = CollectionRun(collector=REQUIRED[0], status=status, reason=reason)
    assert not _coverage_is_baseline_safe(_report(runs))


def test_duplicate_required_collection_is_not_baseline_safe() -> None:
    runs = _complete_required()
    runs.append(runs[0].model_copy())
    assert not _coverage_is_baseline_safe(_report(runs))


def test_complete_required_coverage_allows_unrelated_disabled_collection() -> None:
    runs = _complete_required()
    runs.append(
        CollectionRun(
            collector=CollectionKind.IMAGE,
            status=CollectionRunStatus.DISABLED,
            reason="image_collection_disabled",
        )
    )
    assert _coverage_is_baseline_safe(_report(runs))


def test_snapshot_rejects_missing_declared_form_chunk_even_when_counts_match() -> None:
    second = _snapshot_report(
        "scan-1::chunk-2-of-2",
        assets=[_network_service(1)],
        declared_network_services=1,
    )

    assert not _snapshot_is_baseline_safe([second])


def test_snapshot_rejects_unknown_total_lineage_when_required_count_is_short() -> None:
    first = _snapshot_report(
        "scan-1~report-part-0",
        assets=[_network_service(1)],
        declared_network_services=2,
    )

    assert not _snapshot_is_baseline_safe([first])


def test_snapshot_accepts_complete_lineage_after_deduplicating_asset_ids() -> None:
    first = _snapshot_report(
        "scan-1",
        assets=[_network_service(1)],
        declared_network_services=2,
    )
    second = _snapshot_report(
        "scan-1::chunk-2-of-2",
        assets=[_network_service(1), _network_service(2)],
        declared_network_services=2,
    )

    assert _snapshot_is_baseline_safe([first, second])


class _TailStore:
    def __init__(self, reports: list[AssetReport]) -> None:
        self._reports = reports

    def tail(self, _limit: int) -> list[dict]:
        return [report.model_dump(mode="json") for report in self._reports]

    def append(self, report: AssetReport) -> None:
        self._reports.append(report)


def test_previous_baseline_ignores_incomplete_newest_lineage() -> None:
    prior_time = datetime(2026, 8, 2, tzinfo=UTC)
    incomplete = _snapshot_report(
        "prior",
        collected_at=prior_time,
        assets=[_network_service(1)],
        declared_network_services=2,
    )
    current = _snapshot_report("current")
    state = SimpleNamespace(asset_report_store=_TailStore([incomplete]))

    assert _previous_asset_baseline(current, state).assets is None


def test_previous_baseline_merges_one_complete_logical_lineage() -> None:
    prior_time = datetime(2026, 8, 2, tzinfo=UTC)
    first = _snapshot_report(
        "prior",
        collected_at=prior_time,
        assets=[_network_service(1)],
        declared_network_services=2,
    )
    second = _snapshot_report(
        "prior::chunk-2-of-2",
        collected_at=prior_time,
        assets=[_network_service(2)],
        declared_network_services=2,
    )
    current = _snapshot_report("current")
    state = SimpleNamespace(asset_report_store=_TailStore([first, second]))

    baseline = _previous_asset_baseline(current, state).assets

    assert baseline is not None
    assert {asset.asset_id for asset in baseline} == {"listener-1", "listener-2"}


def test_equal_timestamp_baseline_lineages_are_explicitly_incomplete() -> None:
    prior_time = NOW - timedelta(days=1)
    first = _snapshot_report("prior-a", collected_at=prior_time)
    second = _snapshot_report("prior-b", collected_at=prior_time)
    current = _snapshot_report("current")

    baseline = _previous_asset_baseline(
        current,
        SimpleNamespace(asset_report_store=_TailStore([first, second])),
    )

    assert not baseline.lookup_complete
    assert baseline.assets is None


def test_equal_timestamp_forward_lineages_are_explicitly_incomplete() -> None:
    current = _snapshot_report("current", collected_at=NOW - timedelta(days=1))
    first = _snapshot_report("next-a")
    second = _snapshot_report("next-b")

    future = _next_asset_snapshot(
        current,
        SimpleNamespace(asset_report_store=_TailStore([first, second])),
    )

    assert not future.lookup_complete
    assert future.report is None


def test_snapshot_rejects_children_with_different_provenance() -> None:
    first = _snapshot_report(
        "scan-1::chunk-1-of-2",
        assets=[_network_service(1)],
        declared_network_services=2,
    ).model_copy(update={"source_agent_id": "agent-a", "source_target_id": "target-a"})
    second = _snapshot_report(
        "scan-1::chunk-2-of-2",
        assets=[_network_service(2)],
        declared_network_services=2,
    ).model_copy(update={"source_agent_id": "agent-b", "source_target_id": "target-a"})

    assert not _snapshot_is_baseline_safe([first, second])


def test_current_snapshot_waits_for_final_chunk_then_correlates_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior = _snapshot_report(
        "prior",
        collected_at=datetime(2026, 8, 2, tzinfo=UTC),
        assets=[_network_service(0)],
        declared_network_services=1,
    )
    first = _snapshot_report(
        "current",
        assets=[_network_service(1)],
        declared_network_services=2,
    )
    second = _snapshot_report(
        "current::chunk-2-of-2",
        assets=[_network_service(2)],
        declared_network_services=2,
    )
    state = SimpleNamespace(asset_report_store=_TailStore([prior]))
    correlated: list[tuple[AssetReport, list[NetworkService]]] = []

    def capture_correlation(
        current: AssetReport,
        previous: list[NetworkService],
        _state: SimpleNamespace,
    ) -> ingest_api._DerivedOutcome:
        correlated.append((current, previous))
        return ingest_api._DerivedOutcome()

    monkeypatch.setattr(ingest_api, "_correlate_asset_snapshot", capture_correlation)
    monkeypatch.setattr(
        ingest_api,
        "_auto_detect",
        lambda _report, _state: ingest_api._DerivedOutcome(),
    )

    assert _current_asset_snapshot(first, state) is None
    store_asset_report(first, state)
    assert correlated == []

    store_asset_report(second, state)

    assert len(correlated) == 1
    current, previous = correlated[0]
    assert current.report_id == "current"
    assert {asset.asset_id for asset in current.assets} == {"listener-1", "listener-2"}
    assert {asset.asset_id for asset in previous} == {"listener-0"}


def test_indexed_lineage_and_host_history_survive_global_report_noise(tmp_path) -> None:
    store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
    prior = _snapshot_report(
        "prior",
        collected_at=NOW - timedelta(days=1),
        assets=[_network_service(0)],
        declared_network_services=1,
    )
    first = _snapshot_report(
        "current::chunk-1-of-2",
        assets=[_network_service(1)],
        declared_network_services=2,
    )
    second = _snapshot_report(
        "current::chunk-2-of-2",
        assets=[_network_service(2)],
        declared_network_services=2,
    )
    store.append(prior)
    store.append(first)
    for index in range(ingest_api.CROSS_SOURCE_WINDOW + 1):
        noise = _snapshot_report(f"noise-{index}").model_copy(
            update={
                "host": HostInfo(
                    host_id=f"noise-host-{index}",
                    hostname="noise",
                    os="Linux",
                )
            }
        )
        store.append(noise)
    state = SimpleNamespace(asset_report_store=store)

    current = _current_asset_snapshot(second, state)

    assert current is not None
    assert {asset.asset_id for asset in current.assets} == {"listener-1", "listener-2"}
    baseline = _previous_asset_baseline(current, state)
    assert baseline.lookup_complete
    assert baseline.assets is not None
    assert {asset.asset_id for asset in baseline.assets} == {"listener-0"}


@pytest.mark.parametrize("backend", ["jsonl", "sqlite"])
def test_scoped_lineage_budget_ignores_equal_root_from_other_sources(
    tmp_path, backend: str
) -> None:
    store = (
        JsonlStore(tmp_path / "reports.jsonl", read_max_bytes=2048, fsync=False)
        if backend == "jsonl"
        else SqliteStore(
            tmp_path / "analyzer.db",
            "asset_reports",
            read_max_bytes=2048,
        )
    )
    current = _snapshot_report("shared").model_copy(
        update={"source_agent_id": "agent-a", "source_target_id": "target-a"}
    )
    store.append(current)
    for index in range(1, 40):
        noise = _snapshot_report(f"shared::chunk-{index}-of-39").model_copy(
            update={"source_agent_id": "agent-b", "source_target_id": "target-b"}
        )
        store.append(noise)

    snapshot = _current_asset_snapshot(
        current,
        SimpleNamespace(asset_report_store=store),
    )

    assert snapshot is not None
    assert snapshot.source_agent_id == "agent-a"


def test_exact_second_prior_precedes_fractional_current(tmp_path) -> None:
    store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
    prior = _snapshot_report(
        "prior",
        collected_at=NOW,
        assets=[_network_service(0)],
        declared_network_services=1,
    )
    current = _snapshot_report("current", collected_at=NOW + timedelta(microseconds=1))
    store.append(prior)

    baseline = _previous_asset_baseline(
        current,
        SimpleNamespace(asset_report_store=store),
    )

    assert baseline.assets is not None
    assert {asset.asset_id for asset in baseline.assets} == {"listener-0"}


def test_parallel_chunk_replays_persist_each_deterministic_alert_once(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset_store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
    alert_store = SqliteStore(tmp_path / "analyzer.db", "alerts")
    prior = _snapshot_report(
        "prior",
        collected_at=NOW - timedelta(days=1),
    )
    asset_store.append(prior)

    class _NoDetections:
        def find_one(self, _field: str, _value: str) -> None:
            return None

    state = SimpleNamespace(
        asset_report_store=asset_store,
        alert_store=alert_store,
        vulnerability_store=_NoDetections(),
    )
    monkeypatch.setattr(
        ingest_api,
        "_auto_detect",
        lambda _report, _state: ingest_api._DerivedOutcome(),
    )
    chunks = (
        _snapshot_report(
            "current::chunk-1-of-2",
            assets=[_network_service(1)],
            declared_network_services=2,
        ),
        _snapshot_report(
            "current::chunk-2-of-2",
            assets=[_network_service(2)],
            declared_network_services=2,
        ),
    )
    for chunk in chunks:
        asset_store.append(chunk)
    errors: list[Exception] = []

    def process(chunk: AssetReport) -> None:
        try:
            store_asset_report(chunk, state, persist_raw=False)
        except Exception as exc:  # noqa: BLE001 - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=process, args=(chunk,)) for chunk in chunks]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert not any(thread.is_alive() for thread in threads)
    alerts = alert_store.tail(10)
    assert len(alerts) == 2
    assert len({alert["alert_id"] for alert in alerts}) == 2


def test_crash_replay_rebuilds_snapshot_even_with_existing_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior = _snapshot_report(
        "prior",
        collected_at=NOW - timedelta(days=1),
    )
    current = _snapshot_report(
        "current",
        assets=[_network_service(1)],
        declared_network_services=1,
    )
    asset_store = _TailStore([prior, current])
    detection = DetectionResult(
        report_id=current.report_id,
        host_id=current.host.host_id,
        collected_at=current.collected_at,
        ecosystem="Debian",
        detection_status=DetectionStatus.COMPLETE,
        status_reason=None,
    )

    class _DetectionStore:
        def find_one(self, _field: str, _value: str) -> dict:
            return detection.model_dump(mode="json")

    state = SimpleNamespace(
        asset_report_store=asset_store,
        vulnerability_store=_DetectionStore(),
    )
    correlated: list[tuple[AssetReport, list[NetworkService] | None]] = []

    def capture(
        report: AssetReport,
        previous: list[NetworkService] | None,
        _state: SimpleNamespace,
    ) -> ingest_api._DerivedOutcome:
        correlated.append((report, previous))
        return ingest_api._DerivedOutcome()

    monkeypatch.setattr(ingest_api, "_correlate_asset_snapshot", capture)

    outcome = store_asset_report(current, state, persist_raw=False)

    assert outcome.status == "complete"
    assert len(correlated) == 1
    assert correlated[0][1] == []


def test_older_snapshot_arrival_recomputes_adjacent_newer_delta(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset_store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
    alert_store = SqliteStore(tmp_path / "analyzer.db", "alerts")
    state = SimpleNamespace(asset_report_store=asset_store, alert_store=alert_store)
    zero = _snapshot_report("zero", collected_at=NOW - timedelta(seconds=2))
    older = _snapshot_report(
        "older",
        collected_at=NOW - timedelta(seconds=1),
        assets=[_network_service(1)],
        declared_network_services=1,
    )
    newer = _snapshot_report(
        "newer",
        assets=[_network_service(1)],
        declared_network_services=1,
    )
    monkeypatch.setattr(
        ingest_api,
        "_auto_detect",
        lambda _report, _state: ingest_api._DerivedOutcome(),
    )
    asset_store.append(zero)

    store_asset_report(newer, state)
    assert len(list(_active_alert_rows(alert_store))) == 1

    store_asset_report(older, state)

    alerts = list(_active_alert_rows(alert_store))
    assert len(alerts) == 1
    assert "New non-loopback listener" in alerts[0]["title"]
    assert Alert.model_validate(alerts[0]).created_at == older.collected_at


def test_multiple_late_snapshots_can_reactivate_a_superseded_occurrence(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset_store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
    alert_store = SqliteStore(tmp_path / "analyzer.db", "alerts")
    state = SimpleNamespace(asset_report_store=asset_store, alert_store=alert_store)
    snapshots = {
        "s0": _snapshot_report("s0", collected_at=NOW - timedelta(seconds=3)),
        "s1": _snapshot_report(
            "s1",
            collected_at=NOW - timedelta(seconds=2),
            assets=[_network_service(1)],
            declared_network_services=1,
        ),
        "s2": _snapshot_report("s2", collected_at=NOW - timedelta(seconds=1)),
        "s3": _snapshot_report(
            "s3",
            assets=[_network_service(1)],
            declared_network_services=1,
        ),
    }
    monkeypatch.setattr(
        ingest_api,
        "_auto_detect",
        lambda _report, _state: ingest_api._DerivedOutcome(),
    )
    asset_store.append(snapshots["s0"])

    for name in ("s3", "s1", "s2"):
        store_asset_report(snapshots[name], state)

    active = [Alert.model_validate(row) for row in _active_alert_rows(alert_store)]
    assert len(active) == 2
    assert {alert.created_at for alert in active} == {
        snapshots["s1"].collected_at,
        snapshots["s3"].collected_at,
    }
    assert len({alert.alert_key for alert in active}) == 1


def test_same_report_id_from_two_sources_keeps_occurrences_isolated(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset_store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
    alert_store = SqliteStore(tmp_path / "analyzer.db", "alerts")
    state = SimpleNamespace(asset_report_store=asset_store, alert_store=alert_store)
    monkeypatch.setattr(
        ingest_api,
        "_auto_detect",
        lambda _report, _state: ingest_api._DerivedOutcome(),
    )
    for source in ("agent-a", "agent-b"):
        prior = _snapshot_report("prior", collected_at=NOW - timedelta(seconds=1)).model_copy(
            update={"source_agent_id": source, "source_target_id": "target-1"}
        )
        current = _snapshot_report(
            "shared-report",
            assets=[_network_service(1)],
            declared_network_services=1,
        ).model_copy(update={"source_agent_id": source, "source_target_id": "target-1"})
        asset_store.append(prior)
        store_asset_report(current, state)

    active = [Alert.model_validate(row) for row in _active_alert_rows(alert_store)]
    assert len(active) == 2
    assert len({alert.alert_id for alert in active}) == 2
    assert len({alert.alert_key for alert in active}) == 1


def test_asset_alert_limit_is_explicitly_partial_and_truncated(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset_store = SqliteStore(tmp_path / "analyzer.db", "asset_reports")
    alert_store = SqliteStore(tmp_path / "analyzer.db", "alerts")
    state = SimpleNamespace(asset_report_store=asset_store, alert_store=alert_store)
    prior = _snapshot_report("prior", collected_at=NOW - timedelta(seconds=1))
    runs = _complete_required()
    persistence_index = next(
        index
        for index, run in enumerate(runs)
        if run.collector == CollectionKind.PERSISTENCE_ENTRY
    )
    runs[persistence_index] = runs[persistence_index].model_copy(update={"record_count": 129})
    current = AssetReport(
        report_id="current",
        collected_at=NOW,
        scanner_version="test",
        host=HostInfo(host_id="host-1", hostname="node-1", os="Linux"),
        assets=[
            PersistenceEntry(
                asset_id=f"persistence-{index}",
                entry_type=PersistenceType.SYSTEMD_SERVICE,
                name=f"service-{index}",
                source_path=f"/etc/systemd/system/service-{index}.service",
            )
            for index in range(129)
        ],
        collection_runs=runs,
    )
    asset_store.append(prior)
    monkeypatch.setattr(
        ingest_api,
        "_auto_detect",
        lambda _report, _state: ingest_api._DerivedOutcome(),
    )

    outcome = store_asset_report(current, state)

    assert outcome.status == "partial"
    assert outcome.truncated
    assert outcome.reason == "asset_max_alerts"
    assert len(list(_active_alert_rows(alert_store))) == 128


def test_lineage_read_budget_is_reported_partial(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset_store = SqliteStore(
        tmp_path / "analyzer.db",
        "asset_reports",
        read_max_bytes=1,
    )
    state = SimpleNamespace(asset_report_store=asset_store)
    monkeypatch.setattr(
        ingest_api,
        "_auto_detect",
        lambda _report, _state: ingest_api._DerivedOutcome(),
    )

    outcome = store_asset_report(_snapshot_report("bounded"), state)

    assert outcome.status == "partial"
    assert outcome.reason == "asset_lineage_history_truncated"


def test_huge_declared_chunk_total_fails_closed_without_materializing_range() -> None:
    report = _snapshot_report("huge::chunk-1-of-1000000000")

    assert not _snapshot_is_baseline_safe([report])


def test_unresolved_listener_ownership_is_safe_when_enumeration_inputs_are_complete() -> None:
    runs = _complete_required()
    runs[0] = CollectionRun(
        collector=CollectionKind.NETWORK_SERVICE,
        status=CollectionRunStatus.PARTIAL,
        reason="network_service_ownership_unresolved",
    )
    runs.extend(
        CollectionRun(collector=collector, status=CollectionRunStatus.COMPLETE)
        for collector in (CollectionKind.PORT, CollectionKind.PROCESS)
    )

    assert _coverage_is_baseline_safe(_report(runs))


@pytest.mark.parametrize(
    ("dependency", "status"),
    [
        (CollectionKind.PORT, CollectionRunStatus.PARTIAL),
        (CollectionKind.PROCESS, CollectionRunStatus.FAILED),
    ],
)
def test_unresolved_listener_ownership_still_requires_complete_enumeration_inputs(
    dependency: CollectionKind,
    status: CollectionRunStatus,
) -> None:
    runs = _complete_required()
    runs[0] = CollectionRun(
        collector=CollectionKind.NETWORK_SERVICE,
        status=CollectionRunStatus.PARTIAL,
        reason="network_service_ownership_unresolved",
    )
    runs.extend(
        CollectionRun(
            collector=collector,
            status=status if collector == dependency else CollectionRunStatus.COMPLETE,
            reason="source_incomplete" if collector == dependency else None,
        )
        for collector in (CollectionKind.PORT, CollectionKind.PROCESS)
    )

    assert not _coverage_is_baseline_safe(_report(runs))


def test_other_network_partial_reason_remains_fail_closed() -> None:
    runs = _complete_required()
    runs[0] = CollectionRun(
        collector=CollectionKind.NETWORK_SERVICE,
        status=CollectionRunStatus.PARTIAL,
        reason="network_service_dependencies_incomplete",
    )
    runs.extend(
        CollectionRun(collector=collector, status=CollectionRunStatus.COMPLETE)
        for collector in (CollectionKind.PORT, CollectionKind.PROCESS)
    )

    assert not _coverage_is_baseline_safe(_report(runs))
