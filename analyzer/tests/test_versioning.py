"""Version comparator tests: SemVer, PEP 440, and the ecosystem registry."""

from __future__ import annotations

import pytest

from analyzer.detect.debversion import dpkg_compare
from analyzer.detect.versioning import (
    apk_compare,
    comparator_for,
    pep440_compare,
    rpm_compare,
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
    ("a", "b", "expected"),
    [
        ("0:1.20.4-1.el9", "0:1.20.4-1.el9", 0),
        ("1.20.4-1.el9", "1.20.4-2.el9", -1),  # release bump
        ("0:1.20.4-1.el9", "1:1.0-1.el9", -1),  # epoch dominates
        ("1.20.4-1.el9", "1.20.10-1.el9", -1),  # numeric, not lexical
        ("1.0-1", "1.0~rc1-1", 1),  # tilde pre-release is older
        ("2.0-1", "2.0-1", 0),
        ("1.el8", "1.el9", -1),  # alpha then numeric run
    ],
)
def test_rpm_compare(a: str, b: str, expected: int) -> None:
    assert rpm_compare(a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.2.3-r0", "1.2.3-r0", 0),
        ("1.2.3-r0", "1.2.3-r1", -1),  # revision
        ("1.2.3", "1.2.3-r1", -1),  # implicit r0 < r1
        ("1.2.10", "1.2.9", 1),  # numeric, not lexical
        ("1.0", "1.0.0", -1),  # more components is newer
        ("1.0_alpha1", "1.0", -1),  # pre-release suffix
        ("1.0_alpha", "1.0_beta", -1),
        ("1.0_pre1", "1.0_pre2", -1),
        ("1.0_p1", "1.0", 1),  # post-release suffix
        ("1.0a", "1.0", 1),  # trailing letter
    ],
)
def test_apk_compare(a: str, b: str, expected: int) -> None:
    assert apk_compare(a, b) == expected


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1.2.3", "1.2-rc"),  # "2-r" residue in a numeric part
        ("a.b", "1.0"),  # purely alphabetic part
        ("1.0-r1a", "1.0"),  # malformed revision tail
        ("1.2-rc", "a.b"),
    ],
)
def test_apk_compare_malformed_does_not_raise(a: str, b: str) -> None:
    # Regression: a malformed apk version used to raise ValueError via int(),
    # aborting detection for the whole report. It must now degrade gracefully.
    result = apk_compare(a, b)
    assert result in (-1, 0, 1)
    # Antisymmetry holds even on the degraded (lexical) path.
    assert apk_compare(b, a) == -result


@pytest.mark.parametrize(
    ("ecosystem", "comparator"),
    [
        ("Debian:12", dpkg_compare),
        ("Ubuntu:22.04", dpkg_compare),
        ("PyPI", pep440_compare),
        ("npm", semver_compare),
        ("crates.io", semver_compare),
        ("Go", semver_compare),
        ("Rocky Linux:9", rpm_compare),
        ("AlmaLinux:8", rpm_compare),
        ("Alpine:v3.18", apk_compare),
        ("SomethingNew", semver_compare),  # unknown falls back to semver
    ],
)
def test_comparator_for(ecosystem: str, comparator) -> None:
    assert comparator_for(ecosystem) is comparator
