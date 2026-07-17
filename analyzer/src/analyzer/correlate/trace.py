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
from ..scoring import alert_score, score_for_severity
from .identity import alert_key_for
from .limits import (
    MAX_ALERTS_PER_INGEST,
    MAX_GROUP_LABELS,
    CorrelationLimitState,
    append_unique_bounded,
    bounded_id,
    bounded_text,
)

# Severity ordering for picking the worst match on an indicator.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Re-exported for the rest of correlate (cross / guard import it from here).
__all__ = ["alert_score", "correlate_trace_batch", "score_for_severity"]


@dataclass
class _Group:
    """Accumulates every flow/host/endpoint that hit one indicator in a batch."""

    indicator: str
    indicator_type: IndicatorType
    severity: Severity = Severity.INFO
    categories: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    trace_ids: list[str] = field(default_factory=list)
    # Vantage points (collector ``TraceEvent.host_id``) that *observed* the hit —
    # NOT the scanned assets. Kept for the human-readable description only.
    observer_ids: list[str] = field(default_factory=list)
    # IPs of the flow endpoints involved in this indicator's hits. These are what
    # map back to a real *asset* (via an IP->host index), unlike the observer id.
    endpoint_ips: list[str] = field(default_factory=list)
    evidence_truncated: bool = False

    def observe(
        self,
        trace_id: str,
        observer_id: str,
        endpoint_ips: list[str],
        severity: Severity,
        category: str,
        source: str,
    ) -> None:
        """Record one indicator hit, raising the group's severity to the worst seen."""
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[self.severity]:
            self.severity = severity
        self.evidence_truncated |= append_unique_bounded(
            self.categories, category, MAX_GROUP_LABELS
        )
        self.evidence_truncated |= append_unique_bounded(self.sources, source, MAX_GROUP_LABELS)
        self.evidence_truncated |= append_unique_bounded(self.trace_ids, trace_id)
        self.evidence_truncated |= append_unique_bounded(self.observer_ids, observer_id)
        for ip in endpoint_ips:
            self.evidence_truncated |= append_unique_bounded(self.endpoint_ips, ip)

    def asset_ids(self, ip_index: dict[str, str] | None) -> list[str]:
        """Resolve the involved endpoint IPs to real asset host_ids.

        With an IP->host index (built from ingested AssetReports) the alert links
        the *scanned assets* that talked to the indicator — the join key the
        cross-source correlation needs. Without an index, we fall back to the
        observer ids (legacy behaviour) so a bare IOC alert is still attributable.
        """
        if ip_index:
            resolved: list[str] = []
            for ip in self.endpoint_ips:
                host = ip_index.get(ip)
                if host is not None:
                    append_unique_bounded(resolved, host)
            if resolved:
                return resolved
        return list(self.observer_ids)


def _alert_for_group(batch: TraceBatch, group: _Group, ip_index: dict[str, str] | None) -> Alert:
    categories = "/".join(group.categories)
    asset_ids = group.asset_ids(ip_index)
    title = (
        f"{len(group.trace_ids)} trace(s) matched threat indicator {group.indicator} ({categories})"
    )
    description = (
        f"Indicator {group.indicator} ({group.indicator_type.value}, {categories}) was hit by "
        f"{len(group.trace_ids)} trace(s) observed at {', '.join(group.observer_ids)} "
        f"per feed(s): {', '.join(group.sources)}."
    )

    return Alert(
        alert_id=bounded_id(
            f"alert-ioc-{batch.batch_id}-{group.indicator_type.value}-{group.indicator}"
        ),
        # Stable identity across batches: indicator type + value, no batch_id.
        alert_key=alert_key_for("ioc", group.indicator_type.value, group.indicator),
        severity=group.severity,
        # Blast radius = how many distinct assets hit this indicator.
        score=alert_score(group.severity, len(asset_ids)),
        title=bounded_text(title),
        description=bounded_text(description),
        related_asset_ids=asset_ids,
        related_trace_ids=group.trace_ids,
        evidence_truncated=group.evidence_truncated,
        created_at=batch.collected_at,
    )


def correlate_trace_batch(
    batch: TraceBatch,
    ip_index: dict[str, str] | None = None,
    limit_state: CorrelationLimitState | None = None,
) -> list[Alert]:
    """Emit one Alert per distinct threat indicator hit in the batch.

    ``ip_index`` maps an IP address to the *asset* host_id that owns it (built
    from ingested AssetReports). When supplied, ``Alert.related_asset_ids`` holds
    real asset ids resolved from the flow endpoints, so a downstream join against
    ``DetectionResult.host_id`` actually matches (C3 fix). Without it, the alert
    falls back to the collector observation-point ids.

    Indicators keep first-seen order so output is deterministic.
    """
    groups: dict[tuple[IndicatorType, str], _Group] = {}
    for event in batch.events:
        endpoint_ips = [str(event.src_ip), str(event.dst_ip)]
        for match in event.threat_intel:
            key = (match.indicator_type, match.indicator)
            group = groups.get(key)
            if group is None:
                if len(groups) >= MAX_ALERTS_PER_INGEST:
                    if limit_state is not None:
                        limit_state.mark("trace_max_alerts")
                    continue
                group = _Group(indicator=match.indicator, indicator_type=match.indicator_type)
                groups[key] = group
            group.observe(
                event.trace_id,
                event.host_id,
                endpoint_ips,
                match.severity,
                match.category,
                match.source,
            )

    return [_alert_for_group(batch, group, ip_index) for group in groups.values()]
