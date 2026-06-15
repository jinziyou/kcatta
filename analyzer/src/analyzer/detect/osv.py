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

    @classmethod
    def from_dict(cls, raw: dict) -> OsvRecord:
        """Parse a raw OSV JSON record into an :class:`OsvRecord`, keeping only used fields."""
        refs = [r["url"] for r in raw.get("references", []) if isinstance(r, dict) and r.get("url")]
        return cls(
            id=raw["id"],
            aliases=list(raw.get("aliases", [])),
            affected=list(raw.get("affected", [])),
            references=refs,
            severity_word=_severity_word(raw),
            cvss_vector=_cvss_vector(raw),
            cvss_v4_vector=_cvss_v4_vector(raw),
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
        """Resolve the record's severity, never silently downgrading a critical.

        Order of preference:
          1. a computed CVSS v3 base score (numeric, most precise);
          2. a CVSS v4.0 vector's base severity (C2 fix: many new CVEs ship a
             v4-only vector — without this they'd fall through to MEDIUM and a
             9.x critical would be mislabelled);
          3. a free-text severity word from the OSV record;
          4. MEDIUM, only when nothing else is known.
        """
        score = self.cvss_score()
        if score is not None:
            return severity_from_score(score)
        if self.cvss_v4_vector:
            v4 = severity_from_v4_vector(self.cvss_v4_vector)
            if v4 is not None:
                return v4
        if self.severity_word:
            return _SEVERITY_WORDS.get(self.severity_word.lower(), Severity.MEDIUM)
        return Severity.MEDIUM

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
    """The record's CVSS v3.x vector string (for numeric base-score), if any."""
    for entry in raw.get("severity", []):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("type", "")).startswith("CVSS_V3") and entry.get("score"):
            return entry["score"]
    return None


def _cvss_v4_vector(raw: dict) -> str | None:
    """The record's CVSS v4.0 vector string, if any.

    OSV uses ``type: "CVSS_V4"`` with the vector string under ``score``; newer
    advisories increasingly ship only a v4 vector (no v3), which is exactly the
    case the C2 downgrade bug missed.
    """
    for entry in raw.get("severity", []):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("type", "")).startswith("CVSS_V4") and entry.get("score"):
            return entry["score"]
    return None


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
