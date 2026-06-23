"""Cross-source correlation: join IOC flow alerts with host vulnerability posture."""

from __future__ import annotations

from ..schemas import Alert, AssetReport, DetectionResult, Severity
from .identity import alert_key_for
from .trace import _SEVERITY_RANK, score_for_severity

_HIGH_RISK = frozenset({Severity.HIGH, Severity.CRITICAL})


def ip_host_index(asset_reports: list[AssetReport]) -> dict[str, str]:
    """Map each known IP address to the asset host_id that owns it.

    Built from ingested AssetReports (``host.ip_addrs``). This is the bridge that
    lets IOC alerts — observed at a collector vantage point — be attributed to the
    real *scanned asset* so they can be joined against ``DetectionResult.host_id``
    (C3 fix). Newest report per IP wins (caller passes newest-first).
    """
    index: dict[str, str] = {}
    for report in asset_reports:
        for ip in report.host.ip_addrs:
            index.setdefault(str(ip), report.host.host_id)
    return index


def worst_severity_by_host(detections: list[DetectionResult]) -> dict[str, Severity]:
    """Map each host_id to its worst known vulnerability severity."""
    worst: dict[str, Severity] = {}
    for result in detections:
        for vuln in result.vulnerabilities:
            current = worst.get(result.host_id)
            if current is None or _SEVERITY_RANK[vuln.severity] > _SEVERITY_RANK[current]:
                worst[result.host_id] = vuln.severity
    return worst


def vuln_ids_for_hosts(
    detections: list[DetectionResult],
    host_ids: set[str],
    *,
    min_rank: int,
) -> list[str]:
    """Collect vuln_ids on the given hosts at or above ``min_rank`` severity."""
    ids: list[str] = []
    seen: set[str] = set()
    for result in detections:
        if result.host_id not in host_ids:
            continue
        for vuln in result.vulnerabilities:
            if _SEVERITY_RANK[vuln.severity] < min_rank:
                continue
            if vuln.vuln_id not in seen:
                seen.add(vuln.vuln_id)
                ids.append(vuln.vuln_id)
    return ids


def cross_source_alerts(
    batch_id: str,
    collected_at,
    ioc_alerts: list[Alert],
    detections: list[DetectionResult],
) -> list[Alert]:
    """Emit compound alerts when an IOC hit involves a host with high/critical vulns."""
    host_severity = worst_severity_by_host(detections)
    extras: list[Alert] = []

    for ioc in ioc_alerts:
        risky_hosts = sorted(
            host_id for host_id in ioc.related_asset_ids if host_severity.get(host_id) in _HIGH_RISK
        )
        if not risky_hosts:
            continue

        host_set = set(risky_hosts)
        # Severity is a StrEnum: plain max() would compare alphabetically
        # ('critical' < 'high'), so rank explicitly.
        worst_host_sev = max(
            (host_severity[h] for h in risky_hosts), key=_SEVERITY_RANK.__getitem__
        )
        severity = ioc.severity
        if _SEVERITY_RANK[worst_host_sev] > _SEVERITY_RANK[severity]:
            severity = worst_host_sev

        vuln_ids = vuln_ids_for_hosts(
            detections,
            host_set,
            min_rank=_SEVERITY_RANK[Severity.HIGH],
        )

        title = (
            f"High-risk host(s) {', '.join(risky_hosts)} with known vuln(s) "
            f"also matched threat indicator in: {ioc.title}"
        )
        description = (
            f"Cross-source correlation: host(s) {', '.join(risky_hosts)} have "
            f"high/critical vulnerability findings ({', '.join(vuln_ids) or 'see store'}) "
            f"and also appeared in IOC alert {ioc.alert_id} ({ioc.description})"
        )

        extras.append(
            Alert(
                alert_id=f"alert-cross-{batch_id}-{ioc.alert_id}",
                # Stable identity: the IOC's own stable key + the risky-host set
                # (already sorted), independent of batch_id.
                alert_key=alert_key_for(
                    "cross", ioc.alert_key or ioc.alert_id, ",".join(risky_hosts)
                ),
                severity=severity,
                score=score_for_severity(severity),
                title=title,
                description=description,
                related_asset_ids=risky_hosts,
                related_vuln_ids=vuln_ids,
                related_trace_ids=list(ioc.related_trace_ids),
                created_at=collected_at,
            )
        )

    return extras
