"""Shared risk scoring: the consolidated severity table + blast-radius alert score."""

from __future__ import annotations

from analyzer.schemas import Severity
from analyzer.scoring import SEVERITY_SCORE, alert_score, score_for_severity

SEVS = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def test_score_for_severity_matches_table():
    for s in SEVS:
        assert score_for_severity(s) == SEVERITY_SCORE[s]


def test_single_asset_scores_the_base():
    # An isolated finding (1 — or 0 — affected assets) is unchanged by blast radius.
    for s in SEVS:
        assert alert_score(s, 1) == score_for_severity(s)
    assert alert_score(Severity.HIGH, 0) == score_for_severity(Severity.HIGH)


def test_blast_radius_is_monotonic_and_capped():
    base = score_for_severity(Severity.MEDIUM)
    prev = base
    for n in range(1, 10):
        cur = alert_score(Severity.MEDIUM, n)
        assert cur >= prev
        prev = cur
    # Capped: an arbitrarily large blast radius never exceeds base + cap, nor 100.
    assert alert_score(Severity.MEDIUM, 1000) == min(100.0, base + 12.0)
    assert alert_score(Severity.CRITICAL, 1000) <= 100.0


def test_blast_radius_never_inverts_severity_ordering():
    # Even a maximally-widespread lower tier stays strictly below the next tier's base.
    for lo, hi in zip(SEVS, SEVS[1:], strict=False):  # noqa: B905 - pairwise, lengths differ
        assert alert_score(lo, 1000) < score_for_severity(hi)
