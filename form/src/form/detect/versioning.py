"""Per-ecosystem version comparators.

Vulnerability matching needs "is the installed version older than the fixed
version?" answered with the *native* ordering of each ecosystem:

* Debian / Ubuntu -> dpkg semantics (see :mod:`.debversion`)
* PyPI -> PEP 440 (delegated to ``packaging``)
* npm / Go / crates.io / Packagist / Hex / ... -> SemVer 2.0.0 precedence

:func:`comparator_for` maps an OSV ecosystem string (``"Debian:12"``,
``"PyPI"``, ``"npm"``, ...) to the right comparator. Unknown ecosystems fall
back to SemVer, which covers the large majority of language registries OSV
tracks.
"""

from __future__ import annotations

from collections.abc import Callable
from itertools import zip_longest

from packaging.version import InvalidVersion, Version

from .debversion import dpkg_compare

Comparator = Callable[[str, str], int]

# Ecosystem base names (the part before any ``:<release>`` suffix) that use
# dpkg ordering rather than SemVer.
_DPKG_ECOSYSTEMS = {"debian", "ubuntu"}
_PEP440_ECOSYSTEMS = {"pypi"}


def _split_semver(version: str) -> tuple[list[int], list[str]]:
    """Split a SemVer-ish string into (release numbers, prerelease identifiers).

    Tolerant of a leading ``v`` and of fewer/more than three release numbers.
    Build metadata (after ``+``) is dropped: it does not affect precedence.
    """
    text = version.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    text = text.split("+", 1)[0]
    main, _, pre = text.partition("-")
    release = [int(part) if part.isdigit() else 0 for part in main.split(".")]
    prerelease = pre.split(".") if pre else []
    return release, prerelease


def _compare_prerelease(a: list[str], b: list[str]) -> int:
    # A version without prerelease identifiers outranks one that has them.
    if not a and not b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    for x, y in zip_longest(a, b, fillvalue=None):
        if x is None:
            return -1  # the shorter set of identifiers has lower precedence
        if y is None:
            return 1
        xnum, ynum = x.isdigit(), y.isdigit()
        if xnum and ynum:
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        elif xnum != ynum:
            # Numeric identifiers always rank lower than alphanumeric ones.
            return -1 if xnum else 1
        elif x != y:
            return -1 if x < y else 1
    return 0


def semver_compare(a: str, b: str) -> int:
    """Return -1, 0, or 1 for ``a`` <, ==, > ``b`` under SemVer 2.0.0 precedence."""
    a_rel, a_pre = _split_semver(a)
    b_rel, b_pre = _split_semver(b)
    for x, y in zip_longest(a_rel, b_rel, fillvalue=0):
        if x != y:
            return -1 if x < y else 1
    return _compare_prerelease(a_pre, b_pre)


def pep440_compare(a: str, b: str) -> int:
    """Return -1, 0, or 1 for ``a`` <, ==, > ``b`` under PEP 440.

    Falls back to SemVer ordering if either string is not a valid PEP 440
    version (some OSV records carry non-canonical strings).
    """
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion:
        return semver_compare(a, b)
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def comparator_for(ecosystem: str) -> Comparator:
    """Pick the native version comparator for an OSV ecosystem string."""
    base = ecosystem.split(":", 1)[0].strip().lower()
    if base in _DPKG_ECOSYSTEMS:
        return dpkg_compare
    if base in _PEP440_ECOSYSTEMS:
        return pep440_compare
    return semver_compare
