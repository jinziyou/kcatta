"""Debian package version comparison (dpkg semantics).

A standalone implementation of the algorithm specified in ``deb-version(5)``,
so vulnerability matching can decide "is the installed version older than the
fixed version?" without shelling out to ``dpkg``.

A version is ``[epoch:]upstream_version[-debian_revision]``. Comparison is:
epoch (numeric), then ``upstream_version``, then ``debian_revision``, the
latter two via :func:`_compare_segment`, which alternates non-digit and digit
runs. Within a non-digit run, ``~`` sorts before everything (even end of
string), letters sort before non-letters, and end of string sorts before any
real character. Digit runs compare numerically (leading zeros ignored).
"""

from __future__ import annotations

# Ordering weight of a single character inside a non-digit run.
# ``None`` represents "end of the run" (a missing character).
_END = 0
_TILDE = -1


def _order(char: str | None) -> int:
    if char is None:
        return _END
    if char == "~":
        return _TILDE
    if char.isalpha():
        return ord(char)
    # Any other (non-letter, non-digit, non-tilde) char sorts after letters
    # and after end-of-string.
    return ord(char) + 256


def _split(version: str) -> tuple[int, str, str]:
    """Split into (epoch, upstream_version, debian_revision)."""
    epoch = 0
    rest = version
    if ":" in version:
        head, _, tail = version.partition(":")
        if head.isdigit():
            epoch = int(head)
            rest = tail
    if "-" in rest:
        upstream, _, revision = rest.rpartition("-")
    else:
        upstream, revision = rest, ""
    return epoch, upstream, revision


def _compare_segment(a: str, b: str) -> int:
    ia = ib = 0
    la, lb = len(a), len(b)

    while ia < la or ib < lb:
        # Non-digit run: compare character by character with the dpkg ordering.
        while (ia < la and not a[ia].isdigit()) or (ib < lb and not b[ib].isdigit()):
            ca = a[ia] if ia < la and not a[ia].isdigit() else None
            cb = b[ib] if ib < lb and not b[ib].isdigit() else None
            oa, ob = _order(ca), _order(cb)
            if oa != ob:
                return -1 if oa < ob else 1
            if ca is not None:
                ia += 1
            if cb is not None:
                ib += 1

        # Digit run: numeric comparison, leading zeros ignored.
        while ia < la and a[ia] == "0":
            ia += 1
        while ib < lb and b[ib] == "0":
            ib += 1
        da_start, db_start = ia, ib
        while ia < la and a[ia].isdigit():
            ia += 1
        while ib < lb and b[ib].isdigit():
            ib += 1
        da, db = a[da_start:ia], b[db_start:ib]
        if len(da) != len(db):
            return -1 if len(da) < len(db) else 1
        if da != db:
            return -1 if da < db else 1

    return 0


def dpkg_compare(a: str, b: str) -> int:
    """Return -1, 0, or 1 for ``a`` <, ==, > ``b`` under dpkg version rules."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    if (c := _compare_segment(ua, ub)) != 0:
        return c
    return _compare_segment(ra, rb)
