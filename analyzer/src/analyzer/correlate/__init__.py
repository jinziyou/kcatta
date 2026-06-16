"""Correlation: turn ingested telemetry into actionable Alerts.

v0 ships a single rule -- events annotated with threat-intel IOC matches
(by collector-side preliminary processing) become `Alert`s. This is the
join between "what we observed on the wire" and "what we know is bad".

Cross-source correlation (e.g. a high-CVSS host also talking to a C2) is
implemented in `cross.py` (`cross_source_alerts`); richer joins will follow
alongside `analyzer.normalize`.
"""

from .cross import cross_source_alerts, ip_host_index
from .trace import correlate_trace_batch, score_for_severity

__all__ = [
    "correlate_trace_batch",
    "cross_source_alerts",
    "ip_host_index",
    "score_for_severity",
]
