"""Vulnerability detection engine.

Matches the packages in an :class:`AssetReport` against a local OSV store
and emits :class:`Vulnerability` findings. This is the "self-implemented"
CVE detection: package inventory joined with advisory data, version ranges
evaluated with each ecosystem's native ordering (dpkg / PEP 440 / rpm /
apk / SemVer via :func:`~fusion.detect.versioning.comparator_for`). No external
scanner (trivy/grype) involved.
"""

from __future__ import annotations

import logging
import re

from ..schemas import AssetReport, Package, Vulnerability
from .osv import OsvRecord, is_version_affected
from .store import OsvStore
from .versioning import comparator_for, semver_compare

SOURCE = "osv"

logger = logging.getLogger(__name__)


def ecosystem_for_os(os_string: str) -> str | None:
    """Best-effort map a HostInfo.os string to an OSV ecosystem.

    Examples: ``"Ubuntu 22.04"`` -> ``"Ubuntu:22.04"``,
    ``"Debian GNU/Linux 12 (bookworm)"`` -> ``"Debian:12"``.
    Returns ``None`` for distros OSV does not track (e.g. Kali); callers
    should then require an explicit ecosystem.
    """
    text = os_string.strip()
    lowered = text.lower()
    if "ubuntu" in lowered and (m := re.search(r"(\d+\.\d+)", text)):
        return f"Ubuntu:{m.group(1)}"
    if "debian" in lowered and (m := re.search(r"\b(\d+)\b", text)):
        return f"Debian:{m.group(1)}"
    if "windows" in lowered and (m := re.search(r"\b(1[01]|8\.1|8)\b", text)):
        return f"Windows:{m.group(1)}"
    if "windows" in lowered:
        return "Windows:10"
    return None


def resolve_ecosystem(report: AssetReport, pinned: str | None) -> str | None:
    """Pinned ecosystem if given, else derive from the report's host.os."""
    return pinned or ecosystem_for_os(report.host.os)


def detect_report(
    report: AssetReport,
    store: OsvStore,
    ecosystem: str | None = None,
) -> list[Vulnerability]:
    """Return vulnerabilities for the packages in ``report``.

    Each package is matched under its own ``Package.ecosystem`` when set,
    otherwise under ``ecosystem`` (the host-derived default). This lets a
    single report mix OS packages (e.g. ``Debian:12``) and language packages
    (e.g. ``PyPI``). Packages with no resolvable ecosystem are skipped.
    """
    findings: list[Vulnerability] = []
    seen: set[tuple[str, str]] = set()

    for asset in report.assets:
        if not isinstance(asset, Package):
            continue
        pkg_ecosystem = asset.ecosystem or ecosystem
        if not pkg_ecosystem:
            continue
        compare = comparator_for(pkg_ecosystem)
        for record in store.lookup(pkg_ecosystem, asset.name):
            # Isolate per-record failures: one malformed advisory or version
            # string must not abort detection for the whole report (which would
            # silently drop every other finding). Skip the bad record instead.
            try:
                for entry in record.affected_entries(pkg_ecosystem, asset.name):
                    affected, fixed = is_version_affected(
                        asset.version, entry, compare, semver_compare
                    )
                    if not affected:
                        continue
                    vuln_id = record.primary_id()
                    key = (asset.asset_id, vuln_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(_to_vulnerability(asset, record, vuln_id, fixed))
                    break
            except Exception:  # noqa: BLE001 - one bad record must not abort the report
                logger.warning(
                    "skipping OSV record %s for %s/%s: comparison failed",
                    getattr(record, "id", "?"),
                    pkg_ecosystem,
                    asset.name,
                    exc_info=True,
                )
                continue

    return findings


def _to_vulnerability(
    asset: Package,
    record: OsvRecord,
    vuln_id: str,
    fixed: str | None,
) -> Vulnerability:
    evidence = f"{asset.name} {asset.version} affected by {vuln_id}"
    if fixed:
        evidence += f" (fixed in {fixed})"

    references = list(record.references)
    osv_url = f"https://osv.dev/vulnerability/{record.id}"
    if osv_url not in references:
        references.insert(0, osv_url)

    return Vulnerability(
        vuln_id=vuln_id,
        severity=record.severity(),
        cvss_score=record.cvss_score(),
        affected_asset_id=asset.asset_id,
        source=SOURCE,
        evidence=evidence,
        references=references,
    )
