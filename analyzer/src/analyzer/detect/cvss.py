"""CVSS base score computation (v3.x exact, v4.0 base-severity).

* v3.0 / v3.1 vectors: the exact CVSS v3.1 base-score formula (also valid for
  v3.0 vectors), so findings carry a numeric ``cvss_score`` and a severity
  derived from it.
* v4.0 vectors: CVSS v4.0 introduced a lookup-table (MacroVector) base score
  that we deliberately do not reproduce here. Instead we resolve the qualitative
  **base severity** straight from the vector's Base metrics, conservatively, so
  a v4-only critical can never be silently downgraded to MEDIUM (C2 regression).

Only the Base metric group is used -- Temporal/Environmental are not used for
triage here.

References:
  https://www.first.org/cvss/v3.1/specification-document
  https://www.first.org/cvss/v4.0/specification-document
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


# --------------------------------------------------------------------------
# CVSS v4.0 base severity (no numeric base-score reproduction; see module doc).
# --------------------------------------------------------------------------

# v4.0 Base metrics we read, with their accepted values. A vector missing any of
# these is not a complete v4 Base vector and yields no severity.
_V4_BASE_METRICS: dict[str, frozenset[str]] = {
    "AV": frozenset("NALP"),
    "AC": frozenset("LH"),
    "AT": frozenset("NP"),
    "PR": frozenset("NLH"),
    "UI": frozenset("NPA"),
    "VC": frozenset("HLN"),
    "VI": frozenset("HLN"),
    "VA": frozenset("HLN"),
    "SC": frozenset("HLN"),
    "SI": frozenset("HLN"),
    "SA": frozenset("HLN"),
}

# Ordinal weights for the qualitative roll-up below (higher = worse).
_V4_IMPACT_WEIGHT = {"H": 2, "L": 1, "N": 0}


def is_cvss_v4_vector(vector: str) -> bool:
    """True when ``vector`` is a CVSS v4.0 vector string (``CVSS:4.0/...``)."""
    return vector.strip().upper().startswith("CVSS:4.0/")


def parse_v4_vector(vector: str) -> dict[str, str] | None:
    """Parse a CVSS v4.0 vector into its Base metric map, or None if incomplete.

    Only the mandatory Base metrics are required; optional Threat/Environmental/
    Supplemental metrics are accepted but ignored for base-severity triage.
    """
    if not is_cvss_v4_vector(vector):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        key, sep, val = part.partition(":")
        if sep and key != "CVSS":
            metrics[key] = val
    base: dict[str, str] = {}
    for key, allowed in _V4_BASE_METRICS.items():
        val = metrics.get(key)
        if val not in allowed:
            return None
        base[key] = val
    return base


def severity_from_v4_vector(vector: str) -> Severity | None:
    """Resolve a conservative qualitative severity from a CVSS v4.0 Base vector.

    CVSS v4.0's numeric base score comes from an official MacroVector lookup
    table that we intentionally do not reproduce. We instead bucket on the Base
    metrics directly, biased so a genuinely critical v4-only finding is never
    downgraded to MEDIUM (the C2 regression). Returns None if the vector is not
    a complete v4 Base vector.

    Heuristic (Base metrics only):
      * worst impact across vulnerable + subsequent systems (VC/VI/VA/SC/SI/SA)
      * an "easily reachable" gate: network attack vector, low complexity,
        no attack requirements, no privileges, no user interaction
      CRITICAL  full impact (any HIGH) AND easily reachable
      HIGH      any HIGH impact, OR (mixed LOW impact AND easily reachable)
      MEDIUM    some LOW impact present
      LOW/NONE  no impact at all
    """
    base = parse_v4_vector(vector)
    if base is None:
        return None

    impacts = [base[m] for m in ("VC", "VI", "VA", "SC", "SI", "SA")]
    worst = max(_V4_IMPACT_WEIGHT[i] for i in impacts)

    easily_reachable = (
        base["AV"] == "N"
        and base["AC"] == "L"
        and base["AT"] == "N"
        and base["PR"] == "N"
        and base["UI"] == "N"
    )

    if worst == 0:
        return Severity.INFO
    if worst == 2:  # at least one HIGH impact
        return Severity.CRITICAL if easily_reachable else Severity.HIGH
    # only LOW impacts present
    return Severity.HIGH if easily_reachable else Severity.MEDIUM
