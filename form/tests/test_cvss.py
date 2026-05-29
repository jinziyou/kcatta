"""CVSS v3.1 base-score computation conformance.

Vectors and expected scores are taken from FIRST's published examples /
well-known CVEs, covering scope-unchanged and scope-changed formulas and
the qualitative severity buckets.
"""

from __future__ import annotations

import pytest

from form.detect.cvss import base_score_from_vector, parse_vector, severity_from_score
from form.schemas import Severity


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
