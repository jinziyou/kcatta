"""Shared severity → risk-score mapping and the alert risk score.

One source of truth for the 0-100 risk score, so correlation (alerts) and
prediction (attack paths) cannot drift apart — previously the same
``_SEVERITY_SCORE`` table was duplicated in ``correlate/trace.py`` and
``predict/engine.py``.
"""

from __future__ import annotations

from .schemas import Severity

# Representative risk score per severity tier (0-100).
SEVERITY_SCORE: dict[Severity, float] = {
    Severity.INFO: 10.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 50.0,
    Severity.HIGH: 75.0,
    Severity.CRITICAL: 95.0,
}

# Blast-radius bump: a fixed amount per affected asset beyond the first, capped.
# The cap (12) is strictly below the smallest gap between adjacent tiers (15, the
# INFO→LOW gap), so a widespread finding is lifted *within* its tier band and can
# never overtake the next severity (a high never outranks a critical).
_BLAST_PER_ASSET = 3.0
_BLAST_CAP = 12.0


def score_for_severity(severity: Severity) -> float:
    """Base 0-100 risk score for a severity tier (no blast-radius factor)."""
    return SEVERITY_SCORE[severity]


def alert_score(severity: Severity, blast_radius: int) -> float:
    """Alert risk score: the severity base plus a capped blast-radius bump for how
    many assets the finding spans.

    ``blast_radius`` is the count of affected assets/hosts. One asset scores the
    base (so an isolated finding is unchanged); each additional asset adds a fixed
    amount up to the cap, so a widespread medium outranks an isolated medium while
    the cap keeps every tier strictly below the next.
    """
    base = SEVERITY_SCORE[severity]
    bonus = min(_BLAST_CAP, max(0, blast_radius - 1) * _BLAST_PER_ASSET)
    return min(100.0, base + bonus)
