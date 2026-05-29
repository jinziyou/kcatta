"""CVSS v3.x base score computation.

Implements the CVSS v3.1 base-score formula (also valid for v3.0 vectors)
so findings carry a numeric ``cvss_score`` and a severity derived from it,
rather than relying on free-text severity words. Only the Base metric group
is supported -- Temporal/Environmental are not used for triage here.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math

from ..schemas import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}
# Privileges Required depends on Scope (unchanged vs changed).
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest 1-decimal value >= input (avoids FP drift)."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def _impact(iss: float, scope_changed: bool) -> float:
    if scope_changed:
        return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    return 6.42 * iss


def parse_vector(vector: str) -> dict[str, str] | None:
    """Parse a CVSS vector string into a metric map, or None if base metrics missing."""
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        key, sep, val = part.partition(":")
        if sep and key != "CVSS":
            metrics[key] = val
    if not all(k in metrics for k in _REQUIRED):
        return None
    return metrics


def base_score_from_vector(vector: str) -> float | None:
    """Compute the CVSS base score from a vector string, or None if unparseable."""
    metrics = parse_vector(vector)
    if metrics is None:
        return None

    scope_changed = metrics["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        pr = pr_table[metrics["PR"]]
        conf = _IMPACT[metrics["C"]]
        integ = _IMPACT[metrics["I"]]
        avail = _IMPACT[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    impact = _impact(iss, scope_changed)
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def severity_from_score(score: float) -> Severity:
    """Map a CVSS base score to the qualitative severity rating."""
    if score <= 0.0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL
