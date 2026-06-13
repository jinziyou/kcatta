"""Correlation: turn ingested telemetry into actionable Alerts.

v0 ships a single rule -- flows annotated with threat-intel IOC matches
(by collector-side preliminary processing) become `Alert`s. This is the
join between "what we observed on the wire" and "what we know is bad".

Cross-source correlation (e.g. a high-CVSS host also talking to a C2) is
implemented in `cross.py` (`cross_source_alerts`); richer joins will follow
alongside `analyzer.normalize`.
"""

from .cross import cross_source_alerts
from .flow import correlate_flow_batch, score_for_severity

__all__ = [
    "correlate_flow_batch",
    "cross_source_alerts",
    "score_for_severity",
]
