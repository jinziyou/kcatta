"""Correlate flow threat-intel matches into Alerts.

Rule (v0): aggregate by indicator. Every distinct IOC hit in a batch
becomes one `Alert` that links *all* the events (and hosts) that touched
that indicator. A single flow hitting several distinct indicators thus
contributes to several alerts. The alert severity is the worst severity
reported for that indicator across the batch; its score is derived from
that severity.

Alert ids are deterministic (`alert-ioc-<batch_id>-<type>-<indicator>`)
so re-ingesting the same batch yields stable ids instead of duplicates
downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schemas import Alert, IndicatorType, Severity, TraceBatch

# Severity ordering for picking the worst match on an indicator.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Representative risk score per severity (0-100), used to seed Alert.score.
_SEVERITY_SCORE: dict[Severity, float] = {
    Severity.INFO: 10.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 50.0,
    Severity.HIGH: 75.0,
    Severity.CRITICAL: 95.0,
}


def score_for_severity(severity: Severity) -> float:
    """Return the representative 0-100 risk score for a severity level."""
    return _SEVERITY_SCORE[severity]


@dataclass
class _Group:
    """Accumulates every flow/host that hit one indicator in a batch."""

    indicator: str
    indicator_type: IndicatorType
    severity: Severity = Severity.INFO
    categories: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    trace_ids: list[str] = field(default_factory=list)
    host_ids: list[str] = field(default_factory=list)

    def observe(self, trace_id: str, host_id: str, severity: Severity, category: str, source: str):
        """Record one indicator hit, raising the group's severity to the worst seen."""
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[self.severity]:
            self.severity = severity
        _append_unique(self.categories, category)
        _append_unique(self.sources, source)
        _append_unique(self.trace_ids, trace_id)
        _append_unique(self.host_ids, host_id)


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _alert_for_group(batch: TraceBatch, group: _Group) -> Alert:
    categories = "/".join(group.categories)
    title = (
        f"{len(group.trace_ids)} trace(s) matched threat indicator {group.indicator} ({categories})"
    )
    description = (
        f"Indicator {group.indicator} ({group.indicator_type.value}, {categories}) was hit by "
        f"{len(group.trace_ids)} trace(s) from host(s) {', '.join(group.host_ids)} "
        f"per feed(s): {', '.join(group.sources)}."
    )

    return Alert(
        alert_id=f"alert-ioc-{batch.batch_id}-{group.indicator_type.value}-{group.indicator}",
        severity=group.severity,
        score=score_for_severity(group.severity),
        title=title,
        description=description,
        related_asset_ids=group.host_ids,
        related_trace_ids=group.trace_ids,
        created_at=batch.collected_at,
    )


def correlate_trace_batch(batch: TraceBatch) -> list[Alert]:
    """Emit one Alert per distinct threat indicator hit in the batch.

    Indicators keep first-seen order so output is deterministic.
    """
    groups: dict[tuple[IndicatorType, str], _Group] = {}
    for event in batch.events:
        for match in event.threat_intel:
            key = (match.indicator_type, match.indicator)
            group = groups.get(key)
            if group is None:
                group = _Group(indicator=match.indicator, indicator_type=match.indicator_type)
                groups[key] = group
            group.observe(
                event.trace_id, event.host_id, match.severity, match.category, match.source
            )

    return [_alert_for_group(batch, group) for group in groups.values()]
