"""Security-relevant deltas between consecutive asset snapshots."""

from __future__ import annotations

from datetime import UTC, datetime

from analyzer.correlate import correlate_asset_report
from analyzer.schemas import (
    AssetReport,
    DataService,
    DataServiceCategory,
    HostInfo,
    NetworkService,
    PersistenceEntry,
    PersistenceType,
    SecurityControl,
    SecurityControlStatus,
    SecurityControlType,
    SensitiveFile,
    SensitiveFileCategory,
)

NOW = datetime(2026, 7, 31, tzinfo=UTC)


def _report(*assets) -> AssetReport:
    return AssetReport(
        report_id="report-current",
        collected_at=NOW,
        scanner_version="test",
        host=HostInfo(host_id="host-1", hostname="node-1", os="Linux"),
        assets=list(assets),
    )


def _listener(*, owner: bool, port: int = 5432) -> NetworkService:
    return NetworkService(
        asset_id=f"network-{port}",
        proto="tcp",
        port=port,
        listen_addr="0.0.0.0",
        port_asset_id=f"port-{port}",
        process_asset_id=f"process-{port}" if owner else None,
    )


def _database(*, tls: bool, auth: bool, anonymous: bool) -> DataService:
    return DataService(
        asset_id="database-postgresql",
        category=DataServiceCategory.DATABASE,
        engine="postgresql",
        network_service_ids=["network-5432"],
        tls_enabled=tls,
        authentication_enabled=auth,
        anonymous_access=anonymous,
        discovery_source="process+listener+config",
    )


def _control(status: SecurityControlStatus) -> SecurityControl:
    return SecurityControl(
        asset_id="control-firewall",
        control=SecurityControlType.FIREWALL,
        name="firewalld",
        status=status,
    )


def _sensitive(digest: str) -> SensitiveFile:
    return SensitiveFile(
        asset_id="file-sshd",
        path="/etc/ssh/sshd_config",
        category=SensitiveFileCategory.SSH,
        sha256=digest,
        world_writable=False,
        group_writable=False,
        setuid=False,
        setgid=False,
    )


def _persistence(name: str) -> PersistenceEntry:
    return PersistenceEntry(
        asset_id=f"persistence-{name}",
        entry_type=PersistenceType.SYSTEMD_SERVICE,
        name=name,
        source_path=f"/etc/systemd/system/{name}",
    )


def test_empty_prior_snapshot_establishes_baseline_without_alerts() -> None:
    current = _report(_listener(owner=True), _database(tls=True, auth=True, anonymous=False))
    assert correlate_asset_report(current, []) == []


def test_snapshot_delta_alerts_on_exposure_control_auth_file_and_persistence() -> None:
    previous = _report(
        _listener(owner=True),
        _database(tls=True, auth=True, anonymous=False),
        _control(SecurityControlStatus.ACTIVE),
        _sensitive("a" * 64),
        _persistence("known.service"),
    ).assets
    current = _report(
        _listener(owner=False),
        _listener(owner=True, port=6379),
        _database(tls=False, auth=False, anonymous=True),
        _control(SecurityControlStatus.INACTIVE),
        _sensitive("b" * 64),
        _persistence("known.service"),
        _persistence("new.service"),
    )

    alerts = correlate_asset_report(current, previous)
    titles = {alert.title for alert in alerts}

    assert len(alerts) == 6
    assert all(alert.related_asset_ids[0] == "host-1" for alert in alerts)
    assert any("ownership became unresolved" in title for title in titles)
    assert any("New non-loopback listener" in title for title in titles)
    assert any("Security control degraded" in title for title in titles)
    assert any("posture degraded" in title for title in titles)
    assert any("Sensitive file changed" in title for title in titles)
    assert any("New persistence entry" in title for title in titles)


def test_new_nonloop_database_emits_dedicated_exposure_alert() -> None:
    previous = _report(_control(SecurityControlStatus.ACTIVE)).assets
    current = _report(
        _listener(owner=True),
        _database(tls=True, auth=True, anonymous=False),
        _control(SecurityControlStatus.ACTIVE),
    )

    alerts = correlate_asset_report(current, previous)

    assert any("New exposed database" in alert.title for alert in alerts)
