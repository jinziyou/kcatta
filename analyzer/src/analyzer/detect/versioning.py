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

# Ecosystem base names (the part before any ``:<release>`` suffix), grouped by
# the native version ordering they use.
_DPKG_ECOSYSTEMS = {"debian", "ubuntu"}
_PEP440_ECOSYSTEMS = {"pypi"}
_RPM_ECOSYSTEMS = {
    "rocky linux",
    "almalinux",
    "alma linux",
    "red hat",
    "centos",
    "oracle linux",
    "opensuse",
    "suse",
    "mageia",
}
_APK_ECOSYSTEMS = {"alpine", "chainguard", "wolfi"}


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


def _rpmvercmp(a: str, b: str) -> int:
    """Compare two rpm version *or* release segments (the rpm ``rpmvercmp``).

    Walks both strings, comparing alternating numeric / alphabetic runs.
    Numeric runs win over alphabetic; ``~`` sorts before everything (older);
    ``^`` sorts after (newer). Mirrors rpm's ``lib/rpmvercmp.c``.
    """
    if a == b:
        return 0
    i, j = 0, 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not (a[i].isalnum() or a[i] in "~^"):
            i += 1
        while j < lb and not (b[j].isalnum() or b[j] in "~^"):
            j += 1
        # Tilde: the side that has it is older.
        a_tilde, b_tilde = i < la and a[i] == "~", j < lb and b[j] == "~"
        if a_tilde or b_tilde:
            if not a_tilde:
                return 1
            if not b_tilde:
                return -1
            i, j = i + 1, j + 1
            continue
        # Caret: the side that has it is newer, unless it is at end of string.
        a_caret, b_caret = i < la and a[i] == "^", j < lb and b[j] == "^"
        if a_caret or b_caret:
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if not a_caret:
                return 1
            if not b_caret:
                return -1
            i, j = i + 1, j + 1
            continue
        if not (i < la and j < lb):
            break
        start_i, start_j = i, j
        isnum = a[i].isdigit()
        if isnum:
            while i < la and a[i].isdigit():
                i += 1
            while j < lb and b[j].isdigit():
                j += 1
        else:
            while i < la and a[i].isalpha():
                i += 1
            while j < lb and b[j].isalpha():
                j += 1
        seg_a, seg_b = a[start_i:i], b[start_j:j]
        if seg_b == "":
            # b had the other run type here; numeric outranks alphabetic.
            return 1 if isnum else -1
        if isnum:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def _split_evr(value: str) -> tuple[int, str, str]:
    """Split ``[epoch:]version[-release]`` into ``(epoch, version, release)``."""
    epoch = 0
    rest = value
    head, sep, tail = value.partition(":")
    if sep and head.isdigit():
        epoch, rest = int(head), tail
    version, sep, release = rest.partition("-")
    return epoch, version, release if sep else ""


def rpm_compare(a: str, b: str) -> int:
    """Return -1/0/1 for ``a`` <,==,> ``b`` under rpm EVR ordering."""
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    if (c := _rpmvercmp(va, vb)) != 0:
        return c
    return _rpmvercmp(ra, rb)


# apk suffix ordering: pre-release suffixes sort below the implicit release
# (weight 100), post-release suffixes above it.
_APK_SUFFIX_ORDER = {
    "alpha": 0,
    "beta": 1,
    "pre": 2,
    "rc": 3,
    "cvs": 101,
    "svn": 102,
    "git": 103,
    "hg": 104,
    "p": 105,
}
_APK_RELEASE_ORDER = 100


def _split_apk(value: str) -> tuple[list[str], str, list[tuple[int, int]], int]:
    """Split an apk version into (numeric parts, trailing letter, suffixes, rev)."""
    rev = 0
    core = value.strip()
    dash, sep, tail = core.rpartition("-r")
    if sep and tail.isdigit():
        core, rev = dash, int(tail)

    core, _, suffix_str = core.partition("_")
    suffixes: list[tuple[int, int]] = []
    if suffix_str:
        for chunk in suffix_str.split("_"):
            letters = "".join(c for c in chunk if c.isalpha())
            digits = "".join(c for c in chunk if c.isdigit())
            order = _APK_SUFFIX_ORDER.get(letters, _APK_RELEASE_ORDER)
            suffixes.append((order, int(digits) if digits else 0))

    letter = ""
    if core and core[-1].isalpha():
        letter, core = core[-1], core[:-1]
    parts = core.split(".") if core else []
    return parts, letter, suffixes, rev


def _apk_cmp_numpart(a: str, b: str, first: bool) -> int:
    # The first component is always integer; later components with a leading
    # zero compare as fractions (lexically, right-padded), else as integers.
    if not first and (a.startswith("0") or b.startswith("0")):
        width = max(len(a), len(b))
        a, b = a.ljust(width, "0"), b.ljust(width, "0")
        return 0 if a == b else (-1 if a < b else 1)
    # A malformed component (non-digit residue, e.g. "2-r" from "1.2-rc", or a
    # purely alphabetic part) must not crash detection via int(). Fall back to a
    # lexical comparison instead — matching the defensive posture of the other
    # comparators (semver/pep440 also degrade rather than raise on junk input).
    if not _is_int(a) or not _is_int(b):
        return 0 if a == b else (-1 if a < b else 1)
    ai, bi = int(a or "0"), int(b or "0")
    return 0 if ai == bi else (-1 if ai < bi else 1)


def _is_int(s: str) -> bool:
    """True if ``s`` is a non-negative integer literal (empty counts as 0)."""
    return s == "" or s.isdigit()


def _apk_cmp_suffixes(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> int:
    for i in range(max(len(a), len(b))):
        # A missing suffix behaves like the implicit release marker.
        sa = a[i] if i < len(a) else (_APK_RELEASE_ORDER, 0)
        sb = b[i] if i < len(b) else (_APK_RELEASE_ORDER, 0)
        if sa != sb:
            return -1 if sa < sb else 1
    return 0


def apk_compare(a: str, b: str) -> int:
    """Return -1/0/1 for ``a`` <,==,> ``b`` under Alpine apk version ordering."""
    pa, la_, sa, ra = _split_apk(a)
    pb, lb_, sb, rb = _split_apk(b)
    for idx in range(max(len(pa), len(pb))):
        if idx >= len(pa):
            return -1  # b has more numeric components -> newer
        if idx >= len(pb):
            return 1
        if (c := _apk_cmp_numpart(pa[idx], pb[idx], idx == 0)) != 0:
            return c
    if la_ != lb_:
        return -1 if la_ < lb_ else 1
    if (c := _apk_cmp_suffixes(sa, sb)) != 0:
        return c
    return 0 if ra == rb else (-1 if ra < rb else 1)


def comparator_for(ecosystem: str) -> Comparator:
    """Pick the native version comparator for an OSV ecosystem string."""
    base = ecosystem.split(":", 1)[0].strip().lower()
    if base in _DPKG_ECOSYSTEMS:
        return dpkg_compare
    if base in _PEP440_ECOSYSTEMS:
        return pep440_compare
    if base in _RPM_ECOSYSTEMS:
        return rpm_compare
    if base in _APK_ECOSYSTEMS:
        return apk_compare
    return semver_compare
