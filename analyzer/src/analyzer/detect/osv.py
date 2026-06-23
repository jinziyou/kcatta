"""OSV record model and affected-version matching.

Parses records in the `OSV schema <https://ossf.github.io/osv-schema/>`_
defensively (only the fields we need) and decides whether a concrete package
version falls inside a record's affected ranges, using a caller-supplied
version comparator (dpkg for Debian/Ubuntu).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cmp_to_key

from ..schemas import Severity
from .cvss import base_score_from_vector, severity_from_score, severity_from_v4_vector

Comparator = Callable[[str, str], int]

# OSV "introduced": "0" means "from the beginning of time".
_ZERO = "0"

_SEVERITY_WORDS: dict[str, Severity] = {
    "negligible": Severity.INFO,
    "info": Severity.INFO,
    "unimportant": Severity.LOW,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "important": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# Explicit ordinal ranking for "worst-of" comparisons. Severity is a StrEnum, so
# comparing members lexically is wrong ("high" < "low" < "medium"); rank here.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _word_severity(word: str | None) -> Severity | None:
    """Map a free-text severity word to a :class:`Severity`, or None if unknown."""
    if not word:
        return None
    return _SEVERITY_WORDS.get(word.lower())


@dataclass
class OsvRecord:
    """The subset of an OSV record used for matching and reporting."""

    id: str
    aliases: list[str] = field(default_factory=list)
    affected: list[dict] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    severity_word: str | None = None
    cvss_vector: str | None = None
    # CVSS v4.0 vector (kept separate: we resolve its base *severity* rather than
    # a numeric score, so it must not flow into the v3 base_score_from_vector path).
    cvss_v4_vector: str | None = None
    # OSV `withdrawn` timestamp (RFC3339). When set, the advisory was rescinded by
    # its source and must never produce a finding; the store drops such records.
    withdrawn: str | None = None

    @classmethod
    def from_dict(cls, raw: dict) -> OsvRecord:
        """Parse a raw OSV JSON record into an :class:`OsvRecord`, keeping only used fields."""
        refs = [r["url"] for r in raw.get("references", []) if isinstance(r, dict) and r.get("url")]
        withdrawn = raw.get("withdrawn")
        return cls(
            id=raw["id"],
            aliases=list(raw.get("aliases", [])),
            affected=list(raw.get("affected", [])),
            references=refs,
            severity_word=_severity_word(raw),
            cvss_vector=_cvss_vector(raw),
            cvss_v4_vector=_cvss_v4_vector(raw),
            withdrawn=withdrawn if isinstance(withdrawn, str) and withdrawn else None,
        )

    def primary_id(self) -> str:
        """Prefer a CVE alias for the reported ``vuln_id``; fall back to the OSV id."""
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return self.id

    def cvss_score(self) -> float | None:
        """Compute the CVSS base score from the record's vector, or ``None`` if absent."""
        return base_score_from_vector(self.cvss_vector) if self.cvss_vector else None

    def severity(self) -> Severity:
        """Resolve the record's severity as the WORST signal available.

        A record can carry several severity signals from different sources — a
        computed CVSS v3 base score, a CVSS v4.0 vector's base severity, and a
        free-text severity word — and they can disagree (e.g. a distro rates a
        CVE *Critical* while an attached v3 vector computes only *Medium*).
        Taking one source in fixed priority order silently downgrades whenever a
        less-precise source is the more severe one. Instead take the maximum
        across every signal present, so triage never under-reports. The numeric
        ``cvss_score`` is still reported separately and unchanged.

        Falls back to MEDIUM only when no usable signal is present (a labelled
        record is never reported below MEDIUM).
        """
        candidates: list[Severity] = []
        score = self.cvss_score()
        if score is not None:
            candidates.append(severity_from_score(score))
        if self.cvss_v4_vector:
            v4 = severity_from_v4_vector(self.cvss_v4_vector)
            if v4 is not None:
                candidates.append(v4)
        word = _word_severity(self.severity_word)
        if word is not None:
            candidates.append(word)
        if not candidates:
            return Severity.MEDIUM
        return max(candidates, key=_SEVERITY_RANK.__getitem__)

    def affected_entries(self, ecosystem: str, name: str) -> list[dict]:
        """Return this record's ``affected`` entries that target the given ecosystem/package."""
        out = []
        for entry in self.affected:
            pkg = entry.get("package", {})
            if pkg.get("ecosystem") == ecosystem and pkg.get("name") == name:
                out.append(entry)
        return out


def _severity_word(raw: dict) -> str | None:
    for key in ("database_specific", "ecosystem_specific"):
        section = raw.get(key)
        if isinstance(section, dict):
            value = section.get("severity")
            if isinstance(value, str) and value:
                return value
    # Some records carry the qualitative rating as `baseSeverity` on a severity
    # entry (common alongside CVSS_V4) rather than in *_specific — use it as a
    # word fallback so we never default a labelled finding to MEDIUM.
    for entry in raw.get("severity", []):
        if isinstance(entry, dict):
            value = entry.get("baseSeverity")
            if isinstance(value, str) and value:
                return value
    return None


def _cvss_vector(raw: dict) -> str | None:
    """The record's most severe CVSS v3.x vector string (for numeric base-score).

    A record may carry several CVSS_V3 vectors (e.g. one from NVD and one from a
    distro feed). Returning the first is arbitrary and can under-report; pick the
    vector with the highest computed base score so severity is never understated.
    If no v3 vector parses to a score, fall back to the first v3 vector seen
    (preserves the prior behaviour for malformed-but-present vectors).
    """
    best_vector: str | None = None
    best_score: float | None = None
    for entry in raw.get("severity", []):
        if not isinstance(entry, dict):
            continue
        if not str(entry.get("type", "")).startswith("CVSS_V3"):
            continue
        vector = entry.get("score")
        if not vector:
            continue
        if best_vector is None:
            best_vector = vector
        score = base_score_from_vector(vector)
        if score is not None and (best_score is None or score > best_score):
            best_score = score
            best_vector = vector
    return best_vector


def _cvss_v4_vector(raw: dict) -> str | None:
    """The record's most severe CVSS v4.0 vector string, if any.

    OSV uses ``type: "CVSS_V4"`` with the vector string under ``score``; newer
    advisories increasingly ship only a v4 vector (no v3), which is exactly the
    case the C2 downgrade bug missed. As with v3, a record may list more than one
    v4 vector — pick the one resolving to the worst base severity.
    """
    best_vector: str | None = None
    best_rank: int | None = None
    for entry in raw.get("severity", []):
        if not isinstance(entry, dict):
            continue
        if not str(entry.get("type", "")).startswith("CVSS_V4"):
            continue
        vector = entry.get("score")
        if not vector:
            continue
        if best_vector is None:
            best_vector = vector
        sev = severity_from_v4_vector(vector)
        if sev is not None:
            rank = _SEVERITY_RANK[sev]
            if best_rank is None or rank > best_rank:
                best_rank = rank
                best_vector = vector
    return best_vector


def is_version_affected(
    version: str,
    entry: dict,
    compare: Comparator,
    semver: Comparator | None = None,
) -> tuple[bool, str | None]:
    """Return (affected, fixed_version) for ``version`` against one affected entry.

    Handles the explicit ``versions`` list, ECOSYSTEM ranges (compared with the
    ecosystem-native ``compare``) and SEMVER ranges (compared with ``semver``).
    SEMVER ranges are skipped when ``semver`` is not supplied. Each range type
    carries ``introduced`` / ``fixed`` / ``last_affected`` events.
    """
    if version in (entry.get("versions") or []):
        return True, None

    for rng in entry.get("ranges", []):
        range_type = rng.get("type")
        if range_type == "ECOSYSTEM":
            cmp = compare
        elif range_type == "SEMVER" and semver is not None:
            cmp = semver
        else:
            continue
        affected, fixed = _match_range(version, rng.get("events", []), cmp)
        if affected:
            return True, fixed
    return False, None


def _match_range(
    version: str,
    events: list[dict],
    compare: Comparator,
) -> tuple[bool, str | None]:
    # Project events onto a number line, sort by version ("0" = -infinity),
    # then walk to determine the state at ``version``.
    points: list[tuple[str | None, str]] = []
    for ev in events:
        if "introduced" in ev:
            intro = ev["introduced"]
            points.append((None if intro == _ZERO else intro, "introduced"))
        elif "fixed" in ev:
            points.append((ev["fixed"], "fixed"))
        elif "last_affected" in ev:
            points.append((ev["last_affected"], "last_affected"))

    def _cmp(p: tuple[str | None, str], q: tuple[str | None, str]) -> int:
        vp, vq = p[0], q[0]
        if vp is None:
            return 0 if vq is None else -1
        if vq is None:
            return 1
        return compare(vp, vq)

    points.sort(key=cmp_to_key(_cmp))

    affected = False
    fixed_version: str | None = None
    for point_version, kind in points:
        rel = 1 if point_version is None else compare(version, point_version)
        if kind == "introduced":
            if rel >= 0:
                affected = True
        elif kind == "fixed":
            if rel >= 0:
                affected = False
            elif affected:
                # ``version`` is inside [introduced, fixed): affected, with this
                # ``fixed`` as the remediation. Events are sorted ascending, so
                # any later fixed/introduced describes a higher interval that
                # cannot contain ``version`` — return now rather than letting a
                # larger fixed from a subsequent interval overwrite the remediation.
                return True, point_version
        elif kind == "last_affected" and rel > 0:
            affected = False
    return affected, fixed_version
