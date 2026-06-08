"""dpkg version comparison conformance.

Cases mirror the behaviour of ``dpkg --compare-versions`` (epoch handling,
tilde pre-release ordering, leading-zero numeric equality, revisions).
"""

from __future__ import annotations

import pytest

from fusion.detect.debversion import dpkg_compare


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0", 0),
        ("1.0", "1.0-1", -1),  # absent revision is older than -1
        ("1.0-1", "1.0-2", -1),
        ("1:1.0", "2.0", 1),  # epoch dominates
        ("2.0", "1:1.0", -1),
        ("1.0~rc1", "1.0", -1),  # tilde sorts before release
        ("1.0~rc1", "1.0~rc2", -1),
        ("1.0~~", "1.0~", -1),
        ("1.0a", "1.0", 1),  # letters sort after end-of-string
        ("1.0", "1.0a", -1),
        ("1.0a", "1.0b", -1),
        ("1.01", "1.1", 0),  # leading zeros ignored in numeric runs
        ("3.0.2-0ubuntu1.18", "3.0.2-0ubuntu1.19", -1),
        ("2.3.2-3", "2.3.2-3", 0),
        ("1.2.3", "1.2.10", -1),  # numeric, not lexical
    ],
)
def test_dpkg_compare(a: str, b: str, expected: int) -> None:
    assert dpkg_compare(a, b) == expected
    assert dpkg_compare(b, a) == -expected
