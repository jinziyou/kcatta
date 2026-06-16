"""CVSS v3.1 base-score computation conformance.

Vectors and expected scores are taken from FIRST's published examples /
well-known CVEs, covering scope-unchanged and scope-changed formulas and
the qualitative severity buckets.
"""

from __future__ import annotations

import pytest

from analyzer.detect.cvss import (
    base_score_from_vector,
    is_cvss_v4_vector,
    parse_v4_vector,
    parse_vector,
    severity_from_score,
    severity_from_v4_vector,
)
from analyzer.schemas import Severity


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # scope changed
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),  # no impact
        ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ],
)
def test_base_score(vector: str, expected: float) -> None:
    assert base_score_from_vector(vector) == expected


def test_parse_rejects_incomplete_vector() -> None:
    assert parse_vector("CVSS:3.1/AV:N/AC:L") is None
    assert base_score_from_vector("CVSS:3.1/AV:N/AC:L") is None


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFO),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_severity_from_score(score: float, expected: Severity) -> None:
    assert severity_from_score(score) == expected


# --- CVSS v4.0 base severity (C2 regression) -------------------------------


def test_v4_vector_detection() -> None:
    assert is_cvss_v4_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
    assert not is_cvss_v4_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_v4_parse_requires_full_base_vector() -> None:
    # Missing the v4-only AT metric -> not a complete v4 Base vector.
    assert parse_v4_vector("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H") is None
    # A v3 vector is never a v4 vector.
    assert parse_v4_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        # Full impact, network, no privileges/UI -> CRITICAL (must NOT fall to MEDIUM).
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            Severity.CRITICAL,
        ),
        # High impact but local / requires privileges -> HIGH, not critical.
        (
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            Severity.HIGH,
        ),
        # Only LOW impacts, easily reachable -> HIGH.
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            Severity.HIGH,
        ),
        # Only LOW impact, requires user interaction -> MEDIUM.
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            Severity.MEDIUM,
        ),
        # No impact at all -> INFO.
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            Severity.INFO,
        ),
    ],
)
def test_severity_from_v4_vector(vector: str, expected: Severity) -> None:
    assert severity_from_v4_vector(vector) == expected


def test_severity_from_v4_vector_rejects_non_v4() -> None:
    assert severity_from_v4_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None
