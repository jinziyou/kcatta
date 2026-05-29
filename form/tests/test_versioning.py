"""Version comparator tests: SemVer, PEP 440, and the ecosystem registry."""

from __future__ import annotations

import pytest

from form.detect.debversion import dpkg_compare
from form.detect.versioning import (
    comparator_for,
    pep440_compare,
    semver_compare,
)


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0.0", "1.0.0", 0),
        ("1.0.0", "2.0.0", -1),
        ("2.0.0", "1.9.9", 1),
        ("1.2.0", "1.10.0", -1),  # numeric, not lexical
        ("v1.2.3", "1.2.3", 0),  # leading v tolerated
        ("1.0.0", "1.0", 0),  # missing patch treated as 0
        ("1.0.0+build1", "1.0.0+build2", 0),  # build metadata ignored
        ("1.0.0-alpha", "1.0.0", -1),  # prerelease < release
        ("1.0.0-alpha", "1.0.0-beta", -1),
        ("1.0.0-alpha.1", "1.0.0-alpha", 1),  # more identifiers > fewer
        ("1.0.0-alpha.1", "1.0.0-alpha.2", -1),  # numeric identifier order
        ("1.0.0-1", "1.0.0-alpha", -1),  # numeric ranks below alphanumeric
    ],
)
def test_semver_compare(a: str, b: str, expected: int) -> None:
    assert semver_compare(a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0.0", "1.0.0", 0),
        ("1.0", "1.0.0", 0),  # PEP 440 zero-padding
        ("2.0", "10.0", -1),
        ("1.0a1", "1.0", -1),  # pre-release < final
        ("1.0", "1.0.post1", -1),  # post-release > final
        ("1.0.dev1", "1.0a1", -1),  # dev < pre-release
        ("1!1.0", "2.0", 1),  # epoch dominates
        ("not-a-version", "1.0", -1),  # falls back to semver ordering
    ],
)
def test_pep440_compare(a: str, b: str, expected: int) -> None:
    assert pep440_compare(a, b) == expected


@pytest.mark.parametrize(
    ("ecosystem", "comparator"),
    [
        ("Debian:12", dpkg_compare),
        ("Ubuntu:22.04", dpkg_compare),
        ("PyPI", pep440_compare),
        ("npm", semver_compare),
        ("crates.io", semver_compare),
        ("Go", semver_compare),
        ("SomethingNew", semver_compare),  # unknown falls back to semver
    ],
)
def test_comparator_for(ecosystem: str, comparator) -> None:
    assert comparator_for(ecosystem) is comparator
