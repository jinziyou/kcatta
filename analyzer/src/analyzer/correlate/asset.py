"""Correlate consecutive host inventory snapshots into posture-change alerts."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Iterable

from ..schemas import (
    Alert,
    Asset,
    AssetReport,
    DataService,
    NetworkService,
    PersistenceEntry,
    SecurityControl,
    SecurityControlStatus,
    SecurityControlType,
    SensitiveFile,
    Severity,
)
from ..scoring import alert_score
from .identity import alert_key_for
from .limits import (
    MAX_ALERTS_PER_INGEST,
    MAX_RELATED_IDS,
    CorrelationLimitState,
    bounded_id,
    bounded_text,
)


def _is_non_loopback(address: str) -> bool:
    normalized = address.strip().strip("[]").split("%", 1)[0]
    if normalized in {"", "*", "0.0.0.0", "::"}:
        return True
    try:
        return not ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return normalized.lower() not in {"localhost"}


def _listener_key(item: NetworkService) -> tuple[str, str, int]:
    return item.proto, item.listen_addr, item.port


def _data_key(item: DataService) -> tuple[str, str]:
    return item.category, item.engine.lower()


def _persistence_key(item: PersistenceEntry) -> tuple[str, str, str]:
    return item.entry_type, item.source_path, item.name


def _normalized_control_mode(mode: str | None) -> str:
    normalized = (mode or "").strip().lower()
    return normalized or "unknown"


def _security_control_degradation(
    prior: SecurityControl,
    current: SecurityControl,
) -> str | None:
    if prior.status != SecurityControlStatus.ACTIVE:
        return None
    if current.status != SecurityControlStatus.ACTIVE:
        return f"{prior.name} changed from active to {current.status}"

    prior_mode = _normalized_control_mode(prior.mode)
    current_mode = _normalized_control_mode(current.mode)
    if (
        current.control == SecurityControlType.MAC
        and prior_mode == "enforcing"
        and current_mode in {"permissive", "disabled", "unknown"}
    ):
        return f"{prior.name} enforcement mode changed from enforcing to {current_mode}"
    return None


def _alert(
    report: AssetReport,
    *,
    rule: str,
    identity: Iterable[str],
    severity: Severity,
    title: str,
    description: str,
    related: list[str],
) -> Alert:
    parts = [report.host.host_id, *identity]
    occurrence_scope = [
        report.source_agent_id or "legacy",
        report.source_target_id or "unbound",
        report.report_id,
        *parts,
    ]
    occurrence_digest = hashlib.sha256(
        json.dumps(occurrence_scope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    key_parts = parts
    if report.source_target_id is not None:
        key_parts = [f"target:{report.source_target_id}", *parts]
    elif report.source_agent_id is not None:
        key_parts = [f"source:{report.source_agent_id}", *parts]
    return Alert(
        alert_id=bounded_id(f"alert-asset-{rule}-{occurrence_digest}"),
        alert_key=alert_key_for(f"asset-{rule}", *key_parts),
        severity=severity,
        score=alert_score(severity, 1),
        title=bounded_text(title),
        description=bounded_text(description),
        related_asset_ids=list(dict.fromkeys([report.host.host_id, *related]))[:MAX_RELATED_IDS],
        created_at=report.collected_at,
    )


def correlate_asset_report(
    report: AssetReport,
    previous_assets: Iterable[Asset] | None,
    limit_state: CorrelationLimitState | None = None,
) -> list[Alert]:
    """Return bounded alerts for security-relevant changes from the prior baseline.

    ``None`` represents a missing prior baseline and emits no alerts.  An empty
    iterable is a verified-zero baseline, so a newly exposed listener, data
    service, or persistence entry must still be detected.
    """

    if previous_assets is None:
        return []
    previous = list(previous_assets)

    current_network = {
        _listener_key(item): item for item in report.assets if isinstance(item, NetworkService)
    }
    prior_network = {
        _listener_key(item): item for item in previous if isinstance(item, NetworkService)
    }
    alerts: list[Alert] = []

    for key, item in current_network.items():
        if not _is_non_loopback(item.listen_addr):
            continue
        prior = prior_network.get(key)
        ownership = item.process_asset_id or item.service_asset_id or item.container_id
        prior_ownership = (
            prior.process_asset_id or prior.service_asset_id or prior.container_id
            if prior is not None
            else None
        )
        if prior is None:
            severity = Severity.HIGH if ownership is None else Severity.MEDIUM
            alerts.append(
                _alert(
                    report,
                    rule="new-listener",
                    identity=(item.proto, item.listen_addr, str(item.port)),
                    severity=severity,
                    title=(
                        f"New non-loopback listener {item.proto}://"
                        f"{item.listen_addr}:{item.port} on {report.host.host_id}"
                    ),
                    description=(
                        "A listener absent from the prior host baseline is now exposed. "
                        f"Ownership is {ownership or 'unresolved'}."
                    ),
                    related=[item.asset_id],
                )
            )
        elif prior_ownership is not None and ownership is None:
            alerts.append(
                _alert(
                    report,
                    rule="listener-owner-lost",
                    identity=(item.proto, item.listen_addr, str(item.port)),
                    severity=Severity.HIGH,
                    title=(
                        f"Listener ownership became unresolved for {item.listen_addr}:{item.port}"
                    ),
                    description=(
                        "The prior baseline linked this listener to a process, service, "
                        "or container, but the current snapshot cannot resolve ownership."
                    ),
                    related=[item.asset_id],
                )
            )

    previous_controls = {
        item.control: item for item in previous if isinstance(item, SecurityControl)
    }
    for item in report.assets:
        if not isinstance(item, SecurityControl):
            continue
        prior = previous_controls.get(item.control)
        degradation = _security_control_degradation(prior, item) if prior is not None else None
        if degradation is not None:
            alerts.append(
                _alert(
                    report,
                    rule="security-control-degraded",
                    identity=(item.control,),
                    severity=Severity.HIGH,
                    title=f"Security control degraded: {item.control} on {report.host.host_id}",
                    description=(
                        f"{degradation}; verify whether telemetry or protection was disabled."
                    ),
                    related=[item.asset_id],
                )
            )

    previous_data = {_data_key(item): item for item in previous if isinstance(item, DataService)}
    current_network_by_id = {item.asset_id: item for item in current_network.values()}
    for item in report.assets:
        if not isinstance(item, DataService):
            continue
        prior = previous_data.get(_data_key(item))
        non_loopback = any(
            _is_non_loopback(listener.listen_addr)
            for identifier in item.network_service_ids
            if (listener := current_network_by_id.get(identifier)) is not None
        )
        if prior is None and non_loopback:
            alerts.append(
                _alert(
                    report,
                    rule="new-data-exposure",
                    identity=(item.category, item.engine),
                    severity=Severity.HIGH,
                    title=f"New exposed {item.category}: {item.engine} on {report.host.host_id}",
                    description=(
                        "A database, broker, or cache absent from the prior baseline now "
                        "has a non-loopback listener."
                    ),
                    related=[item.asset_id, *item.network_service_ids],
                )
            )
        if prior is None:
            continue
        degradations: list[str] = []
        if prior.tls_enabled is True and item.tls_enabled is False:
            degradations.append("TLS enabled→disabled")
        if prior.authentication_enabled is True and item.authentication_enabled is False:
            degradations.append("authentication enabled→disabled")
        if prior.anonymous_access is False and item.anonymous_access is True:
            degradations.append("anonymous access disabled→enabled")
        if degradations:
            alerts.append(
                _alert(
                    report,
                    rule="data-auth-degraded",
                    identity=(item.category, item.engine),
                    severity=Severity.HIGH,
                    title=(
                        f"{item.engine} transport/authentication posture degraded on "
                        f"{report.host.host_id}"
                    ),
                    description="; ".join(degradations),
                    related=[item.asset_id, *item.network_service_ids],
                )
            )

    previous_files = {item.path: item for item in previous if isinstance(item, SensitiveFile)}
    for item in report.assets:
        if not isinstance(item, SensitiveFile) or item.sha256 is None:
            continue
        prior = previous_files.get(item.path)
        if prior is not None and prior.sha256 is not None and prior.sha256 != item.sha256:
            alerts.append(
                _alert(
                    report,
                    rule="sensitive-file-changed",
                    identity=(item.path,),
                    severity=Severity.HIGH,
                    title=f"Sensitive file changed: {item.path} on {report.host.host_id}",
                    description=(
                        "The bounded file digest differs from the prior baseline; "
                        "file contents were not collected."
                    ),
                    related=[item.asset_id],
                )
            )

    previous_persistence = {
        _persistence_key(item) for item in previous if isinstance(item, PersistenceEntry)
    }
    for item in report.assets:
        if not isinstance(item, PersistenceEntry):
            continue
        if _persistence_key(item) not in previous_persistence:
            alerts.append(
                _alert(
                    report,
                    rule="new-persistence",
                    identity=(item.entry_type, item.source_path, item.name),
                    severity=Severity.HIGH,
                    title=f"New persistence entry: {item.name} on {report.host.host_id}",
                    description=(
                        f"A new {item.entry_type} entry appeared at {item.source_path}; "
                        "the command is retained only as a redacted summary."
                    ),
                    related=[item.asset_id],
                )
            )

    if len(alerts) > MAX_ALERTS_PER_INGEST and limit_state is not None:
        limit_state.mark("asset_max_alerts")
    return alerts[:MAX_ALERTS_PER_INGEST]
