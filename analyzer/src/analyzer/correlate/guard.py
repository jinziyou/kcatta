"""Correlate guard (real-time protection) events into Alerts.

``agent-respond`` streams live detections — network IOC hits, on-access malware,
IDS signature matches, FIM/behavior. This turns the **high-signal** ones
(network / malware / high-severity IDS) into the same :class:`Alert` shape the
trace path produces, then — like :mod:`analyzer.correlate.cross` for trace —
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
    GuardEventBatch,
    IdsEvent,
    IndicatorType,
    MalwareEvent,
    NetworkEvent,
    Severity,
)
from ..scoring import alert_score
from .cross import vuln_ids_for_hosts, worst_severity_by_host
from .identity import alert_key_for
from .trace import _SEVERITY_RANK

# Guard events are turned into alerts only at or above this severity for IDS
# (IDS is noisy; network/malware hits are alerted at any severity).
_IDS_MIN = _SEVERITY_RANK[Severity.HIGH]

_HIGH_RISK = frozenset({Severity.HIGH, Severity.CRITICAL})


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _worst(current: Severity, candidate: Severity) -> Severity:
    return candidate if _SEVERITY_RANK[candidate] > _SEVERITY_RANK[current] else current


def correlate_guard_batch(batch: GuardEventBatch) -> list[Alert]:
    """Emit alerts for the high-signal guard events in ``batch``.

    Network IOC hits (aggregated per indicator), on-access malware hits
    (aggregated per signature+host), and high-severity IDS matches (per
    signature+host). FIM and behavior events are intentionally not alerted here.
    """
    alerts: list[Alert] = []
    alerts.extend(_network_alerts(batch))
    alerts.extend(_malware_alerts(batch))
    alerts.extend(_ids_alerts(batch))
    return alerts


def _network_alerts(batch: GuardEventBatch) -> list[Alert]:
    groups: dict[tuple[IndicatorType, str], dict] = {}
    for event in batch.events:
        if not isinstance(event, NetworkEvent):
            continue
        group = groups.setdefault(
            (event.indicator_type, event.indicator),
            {"sev": Severity.INFO, "cats": [], "srcs": [], "hosts": [], "acts": [], "n": 0},
        )
        group["sev"] = _worst(group["sev"], event.severity)
        _append_unique(group["cats"], event.category)
        _append_unique(group["srcs"], event.source)
        _append_unique(group["hosts"], event.host_id)
        if event.action_taken.value != "none":
            _append_unique(group["acts"], event.action_taken.value)
        group["n"] += 1

    out: list[Alert] = []
    for (itype, indicator), group in groups.items():
        cats = "/".join(group["cats"])
        action_note = f" Endpoint action(s): {', '.join(group['acts'])}." if group["acts"] else ""
        out.append(
            Alert(
                alert_id=f"alert-guard-net-{batch.batch_id}-{itype.value}-{indicator}",
                # Same key formula as the trace IOC path → guard + tap hits fold.
                alert_key=alert_key_for("ioc", itype.value, indicator),
                severity=group["sev"],
                # Blast radius = how many hosts hit this indicator.
                score=alert_score(group["sev"], len(group["hosts"])),
                title=(
                    f"{group['n']} live connection(s) matched threat indicator "
                    f"{indicator} ({cats})"
                ),
                description=(
                    f"agent-respond observed {group['n']} live connection(s) to indicator "
                    f"{indicator} ({itype.value}, {cats}) on host(s) "
                    f"{', '.join(group['hosts'])} per feed(s): {', '.join(group['srcs'])}."
                    f"{action_note}"
                ),
                related_asset_ids=group["hosts"],
                created_at=batch.collected_at,
            )
        )
    return out


def _malware_alerts(batch: GuardEventBatch) -> list[Alert]:
    groups: dict[tuple[str, str], dict] = {}
    for event in batch.events:
        if not isinstance(event, MalwareEvent):
            continue
        group = groups.setdefault(
            (event.signature, event.host_id),
            {"sev": Severity.INFO, "paths": [], "srcs": [], "acts": [], "n": 0},
        )
        group["sev"] = _worst(group["sev"], event.severity)
        _append_unique(group["paths"], event.path)
        _append_unique(group["srcs"], event.source)
        if event.action_taken.value != "none":
            _append_unique(group["acts"], event.action_taken.value)
        group["n"] += 1

    out: list[Alert] = []
    for (signature, host_id), group in groups.items():
        action_note = f" Endpoint action(s): {', '.join(group['acts'])}." if group["acts"] else ""
        out.append(
            Alert(
                alert_id=f"alert-guard-mal-{batch.batch_id}-{host_id}-{signature}",
                alert_key=alert_key_for("guard-malware", signature, host_id),
                severity=group["sev"],
                # Single-host finding: blast radius 1 → severity base.
                score=alert_score(group["sev"], 1),
                title=f"Malware signature {signature} detected on {host_id} ({group['n']} hit(s))",
                description=(
                    f"agent-respond on-access scan flagged {group['n']} file(s) as {signature} "
                    f"on host {host_id}: {', '.join(group['paths'])} "
                    f"(scanner: {', '.join(group['srcs'])}).{action_note}"
                ),
                related_asset_ids=[host_id],
                created_at=batch.collected_at,
            )
        )
    return out


def _ids_alerts(batch: GuardEventBatch) -> list[Alert]:
    groups: dict[tuple[str, str], dict] = {}
    for event in batch.events:
        if not isinstance(event, IdsEvent):
            continue
        if _SEVERITY_RANK[event.severity] < _IDS_MIN:
            continue  # IDS is noisy: only alert on high/critical signatures
        group = groups.setdefault(
            (event.signature_id, event.host_id),
            {"sev": Severity.INFO, "name": event.signature_name, "n": 0},
        )
        group["sev"] = _worst(group["sev"], event.severity)
        group["n"] += 1

    out: list[Alert] = []
    for (signature_id, host_id), group in groups.items():
        out.append(
            Alert(
                alert_id=f"alert-guard-ids-{batch.batch_id}-{host_id}-{signature_id}",
                alert_key=alert_key_for("guard-ids", signature_id, host_id),
                severity=group["sev"],
                # Single-host finding: blast radius 1 → severity base.
                score=alert_score(group["sev"], 1),
                title=f"IDS signature {group['name']} ({signature_id}) fired on {host_id}",
                description=(
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
) -> list[Alert]:
    """Emit compound alerts when a guard detection hits a high/critical-vuln host.

    Mirrors :func:`analyzer.correlate.cross.cross_source_alerts` but for guard
    alerts, joining on their native ``related_asset_ids`` (host_ids) against the
    worst known vulnerability severity per host.
    """
    host_severity = worst_severity_by_host(detections)
    extras: list[Alert] = []

    for guard in guard_alerts:
        risky_hosts = sorted(
            host_id
            for host_id in guard.related_asset_ids
            if host_severity.get(host_id) in _HIGH_RISK
        )
        if not risky_hosts:
            continue

        worst_host_sev = max(
            (host_severity[h] for h in risky_hosts), key=_SEVERITY_RANK.__getitem__
        )
        severity = _worst(guard.severity, worst_host_sev)
        vuln_ids = vuln_ids_for_hosts(
            detections, set(risky_hosts), min_rank=_SEVERITY_RANK[Severity.HIGH]
        )

        extras.append(
            Alert(
                alert_id=f"alert-guard-cross-{batch_id}-{guard.alert_id}",
                alert_key=alert_key_for(
                    "cross-guard", guard.alert_key or guard.alert_id, ",".join(risky_hosts)
                ),
                severity=severity,
                score=alert_score(severity, len(risky_hosts)),
                title=(
                    f"High-risk host(s) {', '.join(risky_hosts)} with known vuln(s) "
                    f"also hit by guard detection: {guard.title}"
                ),
                description=(
                    f"Cross-source correlation: host(s) {', '.join(risky_hosts)} have "
                    f"high/critical vulnerability findings ({', '.join(vuln_ids) or 'see store'}) "
                    f"and also produced guard alert {guard.alert_id} ({guard.description})"
                ),
                related_asset_ids=risky_hosts,
                related_vuln_ids=vuln_ids,
                created_at=collected_at,
            )
        )

    return extras
