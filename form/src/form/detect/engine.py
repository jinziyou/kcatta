"""Vulnerability detection engine.

Matches the packages in an :class:`AssetReport` against a local OSV store
and emits :class:`Vulnerability` findings. This is the "self-implemented"
CVE detection: package inventory joined with advisory data, version ranges
evaluated with dpkg semantics. No external scanner (trivy/grype) involved.
"""

from __future__ import annotations

import re

from ..schemas import AssetReport, Package, Vulnerability
from .debversion import dpkg_compare
from .osv import OsvRecord, is_version_affected
from .store import OsvStore

SOURCE = "osv"


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
    return None


def resolve_ecosystem(report: AssetReport, pinned: str | None) -> str | None:
    """Pinned ecosystem if given, else derive from the report's host.os."""
    return pinned or ecosystem_for_os(report.host.os)


def detect_report(
    report: AssetReport,
    store: OsvStore,
    ecosystem: str,
) -> list[Vulnerability]:
    """Return vulnerabilities for the packages in ``report`` under ``ecosystem``."""
    findings: list[Vulnerability] = []
    seen: set[tuple[str, str]] = set()

    for asset in report.assets:
        if not isinstance(asset, Package):
            continue
        for record in store.lookup(ecosystem, asset.name):
            for entry in record.affected_entries(ecosystem, asset.name):
                affected, fixed = is_version_affected(asset.version, entry, dpkg_compare)
                if not affected:
                    continue
                vuln_id = record.primary_id()
                key = (asset.asset_id, vuln_id)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_to_vulnerability(asset, record, vuln_id, fixed))
                break

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
