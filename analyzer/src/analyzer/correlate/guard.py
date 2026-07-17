"""Correlate guard (real-time protection) events into Alerts.

``agent-respond`` streams live detections — network IOC hits, on-access malware,
IDS signature matches, FIM, and process/behavior findings. Every normalized
guard detection becomes the same :class:`Alert` shape the trace path produces,
then — like :mod:`analyzer.correlate.cross` for trace —
raises compound alerts when a detection lands on a host already known to carry
high/critical vulnerabilities.

Two choices tie it into the rest of the platform:

* **Native host join.** Guard events already carry the scanned asset's
  ``host_id``, so alerts link the real host directly — no IP→asset index needed
  (unlike trace, whose endpoints are vantage-point IPs).
* **Shared identity.** A guard ``NetworkEvent`` IOC hit derives the *same*
  ``alert_key`` as a trace IOC hit on that indicator
  (``alert_key_for("ioc", type, indicator)``), so a C2 seen by both the guard
  and the network tap folds into one triageable alert instead of two.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..schemas import (
    Alert,
    FileIntegrityEvent,
    GuardEventBatch,
    IdsEvent,
    IndicatorType,
    MalwareEvent,
    NetworkEvent,
    ProcessEvent,
    Severity,
)
from ..scoring import alert_score
from .cross import vuln_ids_for_hosts, worst_severity_by_host
from .identity import alert_key_for
from .limits import (
    MAX_ALERTS_PER_INGEST,
    MAX_GROUP_LABELS,
    MAX_RELATED_IDS,
    CorrelationLimitState,
    append_unique_bounded,
    bounded_id,
    bounded_text,
)
from .trace import _SEVERITY_RANK

_HIGH_RISK = frozenset({Severity.HIGH, Severity.CRITICAL})


def _worst(current: Severity, candidate: Severity) -> Severity:
    return candidate if _SEVERITY_RANK[candidate] > _SEVERITY_RANK[current] else current


def _append_group(group: dict, field: str, value: str, limit: int = MAX_RELATED_IDS) -> None:
    group["truncated"] = bool(group.get("truncated")) or append_unique_bounded(
        group[field], value, limit
    )


def correlate_guard_batch(
    batch: GuardEventBatch,
    limit_state: CorrelationLimitState | None = None,
) -> list[Alert]:
    """Emit alerts for the high-signal guard events in ``batch``.

    Each kind is aggregated under a stable content-derived key so lifecycle
    triage/de-duplication applies equally to FIM, behavior, malware, IOC, and IDS.
    """
    alerts: list[Alert] = []
    alerts.extend(_fim_alerts(batch, limit_state))
    alerts.extend(_process_alerts(batch, limit_state))
    alerts.extend(_network_alerts(batch, limit_state))
    alerts.extend(_malware_alerts(batch, limit_state))
    alerts.extend(_ids_alerts(batch, limit_state))
    if len(alerts) > MAX_ALERTS_PER_INGEST and limit_state is not None:
        limit_state.mark("guard_max_alerts")
    return alerts[:MAX_ALERTS_PER_INGEST]


def _fim_alerts(batch: GuardEventBatch, limit_state: CorrelationLimitState | None) -> list[Alert]:
    groups: dict[tuple[str, str, str], dict] = {}
    for event in batch.events:
        if not isinstance(event, FileIntegrityEvent):
            continue
        key = (event.host_id, event.path, event.change_type.value)
        if key not in groups and len(groups) >= MAX_ALERTS_PER_INGEST:
            if limit_state is not None:
                limit_state.mark("guard_fim_max_alerts")
            continue
        group = groups.setdefault(
            key,
            {"sev": Severity.INFO, "acts": [], "n": 0, "truncated": False},
        )
        group["sev"] = _worst(group["sev"], event.severity)
        if event.action_taken.value != "none":
            _append_group(group, "acts", event.action_taken.value, MAX_GROUP_LABELS)
        group["n"] += 1

    out: list[Alert] = []
    for (host_id, path, change_type), group in groups.items():
        action_note = f" Endpoint action(s): {', '.join(group['acts'])}." if group["acts"] else ""
        out.append(
            Alert(
                alert_id=bounded_id(
                    f"alert-guard-fim-{batch.batch_id}-{host_id}-{change_type}-{path}"
                ),
                alert_key=alert_key_for("guard-fim", host_id, change_type, path),
                severity=group["sev"],
                score=alert_score(group["sev"], 1),
                title=bounded_text(f"File integrity {change_type}: {path} on {host_id}"),
                description=bounded_text(
                    f"agent-respond observed {group['n']} {change_type} event(s) for "
                    f"{path} on host {host_id}.{action_note}"
                ),
                related_asset_ids=[host_id],
                evidence_truncated=group["truncated"],
                created_at=batch.collected_at,
            )
        )
    return out


def _process_alerts(
    batch: GuardEventBatch, limit_state: CorrelationLimitState | None
) -> list[Alert]:
    groups: dict[tuple[str, str, str], dict] = {}
    for event in batch.events:
        if not isinstance(event, ProcessEvent):
            continue
        key = (event.host_id, event.rule_id, event.process_name)
        if key not in groups and len(groups) >= MAX_ALERTS_PER_INGEST:
            if limit_state is not None:
                limit_state.mark("guard_process_max_alerts")
            continue
        group = groups.setdefault(
            key,
            {
                "sev": Severity.INFO,
                "behaviors": [],
                "evidence": [],
                "pids": [],
                "n": 0,
                "truncated": False,
            },
        )
        group["sev"] = _worst(group["sev"], event.severity)
        _append_group(group, "behaviors", event.behavior, MAX_GROUP_LABELS)
        _append_group(group, "pids", str(event.pid), MAX_GROUP_LABELS)
        if event.evidence:
            _append_group(group, "evidence", event.evidence, MAX_GROUP_LABELS)
        group["n"] += 1

    out: list[Alert] = []
    for (host_id, rule_id, process_name), group in groups.items():
        evidence_note = f" Evidence: {', '.join(group['evidence'])}." if group["evidence"] else ""
        out.append(
            Alert(
                alert_id=bounded_id(
                    f"alert-guard-process-{batch.batch_id}-{host_id}-{rule_id}-{process_name}"
                ),
                alert_key=alert_key_for("guard-process", host_id, rule_id, process_name),
                severity=group["sev"],
                score=alert_score(group["sev"], 1),
                title=bounded_text(
                    f"Process behavior rule {rule_id} fired for {process_name} on {host_id}"
                ),
                description=bounded_text(
                    f"agent-respond observed {group['n']} process event(s) for {process_name} "
                    f"(PID(s) {', '.join(group['pids'])}) on host {host_id}; behavior(s): "
                    f"{', '.join(group['behaviors'])}.{evidence_note}"
                ),
                related_asset_ids=[host_id],
                evidence_truncated=group["truncated"],
                created_at=batch.collected_at,
            )
        )
    return out


def _network_alerts(
    batch: GuardEventBatch, limit_state: CorrelationLimitState | None
) -> list[Alert]:
    groups: dict[tuple[IndicatorType, str], dict] = {}
    for event in batch.events:
        if not isinstance(event, NetworkEvent):
            continue
        key = (event.indicator_type, event.indicator)
        if key not in groups and len(groups) >= MAX_ALERTS_PER_INGEST:
            if limit_state is not None:
                limit_state.mark("guard_network_max_alerts")
            continue
        group = groups.setdefault(
            key,
            {
                "sev": Severity.INFO,
                "cats": [],
                "srcs": [],
                "hosts": [],
                "acts": [],
                "n": 0,
                "truncated": False,
            },
        )
        group["sev"] = _worst(group["sev"], event.severity)
        _append_group(group, "cats", event.category, MAX_GROUP_LABELS)
        _append_group(group, "srcs", event.source, MAX_GROUP_LABELS)
        _append_group(group, "hosts", event.host_id)
        if event.action_taken.value != "none":
            _append_group(group, "acts", event.action_taken.value, MAX_GROUP_LABELS)
        group["n"] += 1

    out: list[Alert] = []
    for (itype, indicator), group in groups.items():
        cats = "/".join(group["cats"])
        action_note = f" Endpoint action(s): {', '.join(group['acts'])}." if group["acts"] else ""
        out.append(
            Alert(
                alert_id=bounded_id(f"alert-guard-net-{batch.batch_id}-{itype.value}-{indicator}"),
                # Same key formula as the trace IOC path → guard + tap hits fold.
                alert_key=alert_key_for("ioc", itype.value, indicator),
                severity=group["sev"],
                # Blast radius = how many hosts hit this indicator.
                score=alert_score(group["sev"], len(group["hosts"])),
                title=bounded_text(
                    f"{group['n']} live connection(s) matched threat indicator {indicator} ({cats})"
                ),
                description=bounded_text(
                    f"agent-respond observed {group['n']} live connection(s) to indicator "
                    f"{indicator} ({itype.value}, {cats}) on host(s) "
                    f"{', '.join(group['hosts'])} per feed(s): {', '.join(group['srcs'])}."
                    f"{action_note}"
                ),
                related_asset_ids=group["hosts"],
                evidence_truncated=group["truncated"],
                created_at=batch.collected_at,
            )
        )
    return out


def _malware_alerts(
    batch: GuardEventBatch, limit_state: CorrelationLimitState | None
) -> list[Alert]:
    groups: dict[tuple[str, str], dict] = {}
    for event in batch.events:
        if not isinstance(event, MalwareEvent):
            continue
        key = (event.signature, event.host_id)
        if key not in groups and len(groups) >= MAX_ALERTS_PER_INGEST:
            if limit_state is not None:
                limit_state.mark("guard_malware_max_alerts")
            continue
        group = groups.setdefault(
            key,
            {
                "sev": Severity.INFO,
                "paths": [],
                "srcs": [],
                "acts": [],
                "n": 0,
                "truncated": False,
            },
        )
        group["sev"] = _worst(group["sev"], event.severity)
        _append_group(group, "paths", event.path, MAX_GROUP_LABELS)
        _append_group(group, "srcs", event.source, MAX_GROUP_LABELS)
        if event.action_taken.value != "none":
            _append_group(group, "acts", event.action_taken.value, MAX_GROUP_LABELS)
        group["n"] += 1

    out: list[Alert] = []
    for (signature, host_id), group in groups.items():
        action_note = f" Endpoint action(s): {', '.join(group['acts'])}." if group["acts"] else ""
        out.append(
            Alert(
                alert_id=bounded_id(f"alert-guard-mal-{batch.batch_id}-{host_id}-{signature}"),
                alert_key=alert_key_for("guard-malware", signature, host_id),
                severity=group["sev"],
                # Single-host finding: blast radius 1 → severity base.
                score=alert_score(group["sev"], 1),
                title=bounded_text(
                    f"Malware signature {signature} detected on {host_id} ({group['n']} hit(s))"
                ),
                description=bounded_text(
                    f"agent-respond on-access scan flagged {group['n']} file(s) as {signature} "
                    f"on host {host_id}: {', '.join(group['paths'])} "
                    f"(scanner: {', '.join(group['srcs'])}).{action_note}"
                ),
                related_asset_ids=[host_id],
                evidence_truncated=group["truncated"],
                created_at=batch.collected_at,
            )
        )
    return out


def _ids_alerts(batch: GuardEventBatch, limit_state: CorrelationLimitState | None) -> list[Alert]:
    groups: dict[tuple[str, str], dict] = {}
    for event in batch.events:
        if not isinstance(event, IdsEvent):
            continue
        key = (event.signature_id, event.host_id)
        if key not in groups and len(groups) >= MAX_ALERTS_PER_INGEST:
            if limit_state is not None:
                limit_state.mark("guard_ids_max_alerts")
            continue
        group = groups.setdefault(
            key,
            {"sev": Severity.INFO, "name": event.signature_name, "n": 0},
        )
        group["sev"] = _worst(group["sev"], event.severity)
        group["n"] += 1

    out: list[Alert] = []
    for (signature_id, host_id), group in groups.items():
        out.append(
            Alert(
                alert_id=bounded_id(f"alert-guard-ids-{batch.batch_id}-{host_id}-{signature_id}"),
                alert_key=alert_key_for("guard-ids", signature_id, host_id),
                severity=group["sev"],
                # Single-host finding: blast radius 1 → severity base.
                score=alert_score(group["sev"], 1),
                title=bounded_text(
                    f"IDS signature {group['name']} ({signature_id}) fired on {host_id}"
                ),
                description=bounded_text(
                    f"agent-respond IDS matched signature {group['name']} ({signature_id}) "
                    f"{group['n']} time(s) on host {host_id}."
                ),
                related_asset_ids=[host_id],
                created_at=batch.collected_at,
            )
        )
    return out


def guard_compound_alerts(
    batch_id: str,
    collected_at,  # noqa: ANN001 - Timestamp, kept loose to mirror cross_source_alerts
    guard_alerts: Iterable[Alert],
    detections: list,
    limit_state: CorrelationLimitState | None = None,
) -> list[Alert]:
    """Emit compound alerts when a guard detection hits a high/critical-vuln host.

    Mirrors :func:`analyzer.correlate.cross.cross_source_alerts` but for guard
    alerts, joining on their native ``related_asset_ids`` (host_ids) against the
    worst known vulnerability severity per host.
    """
    host_severity = worst_severity_by_host(detections)
    extras: list[Alert] = []

    for guard in guard_alerts:
        all_risky_hosts = sorted(
            {
                host_id
                for host_id in guard.related_asset_ids
                if host_severity.get(host_id) in _HIGH_RISK
            }
        )
        if not all_risky_hosts:
            continue
        if len(extras) >= MAX_ALERTS_PER_INGEST:
            if limit_state is not None:
                limit_state.mark("guard_cross_max_alerts")
            continue

        evidence_limit = CorrelationLimitState()
        risky_hosts = all_risky_hosts[:MAX_RELATED_IDS]
        if len(all_risky_hosts) > len(risky_hosts):
            evidence_limit.mark("guard_cross_related_asset_ids")

        worst_host_sev = max(
            (host_severity[h] for h in risky_hosts), key=_SEVERITY_RANK.__getitem__
        )
        severity = _worst(guard.severity, worst_host_sev)
        vuln_ids = vuln_ids_for_hosts(
            detections,
            set(risky_hosts),
            min_rank=_SEVERITY_RANK[Severity.HIGH],
            limit_state=evidence_limit,
        )
        evidence_truncated = guard.evidence_truncated or evidence_limit.truncated
        if evidence_truncated and limit_state is not None:
            limit_state.mark(evidence_limit.reason or "guard_cross_source_evidence")

        extras.append(
            Alert(
                alert_id=bounded_id(f"alert-guard-cross-{batch_id}-{guard.alert_id}"),
                alert_key=alert_key_for(
                    "cross-guard", guard.alert_key or guard.alert_id, ",".join(risky_hosts)
                ),
                severity=severity,
                score=alert_score(severity, len(risky_hosts)),
                title=bounded_text(
                    f"High-risk host(s) {', '.join(risky_hosts)} with known vuln(s) "
                    f"also hit by guard detection: {guard.title}"
                ),
                description=bounded_text(
                    f"Cross-source correlation: host(s) {', '.join(risky_hosts)} have "
                    f"high/critical vulnerability findings ({', '.join(vuln_ids) or 'see store'}) "
                    f"and also produced guard alert {guard.alert_id} ({guard.description})"
                ),
                related_asset_ids=risky_hosts,
                related_vuln_ids=vuln_ids,
                evidence_truncated=evidence_truncated,
                created_at=collected_at,
            )
        )

    return extras
