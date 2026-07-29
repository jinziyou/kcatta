"""Vulnerability detection engine.

Matches the packages in an :class:`AssetReport` against a local OSV store
and emits :class:`Vulnerability` findings. This is the "self-implemented"
CVE detection: package inventory joined with advisory data, version ranges
evaluated with each ecosystem's native ordering (dpkg / PEP 440 / rpm /
apk / SemVer via :func:`~analyzer.detect.versioning.comparator_for`). No external
scanner (trivy/grype) involved.
"""

from __future__ import annotations

import logging
import re

from ..schemas import AssetReport, Package, Vulnerability
from .limits import MAX_FINDING_BYTES, MAX_FINDINGS, FindingLimitState
from .osv import OsvRecord, is_version_affected
from .store import OsvStore
from .versioning import comparator_for, semver_compare

SOURCE = "osv"

logger = logging.getLogger(__name__)


def _first_standalone_ascii_number(text: str) -> str | None:
    """Return the first ASCII digit run bounded by non-word characters.

    This is the linear-time equivalent of searching for ``\\b(\\d+)\\b``.
    The regular expression can backtrack quadratically on an untrusted string
    containing a long digit run followed by an underscore.
    """
    start: int | None = None
    for index, char in enumerate(text):
        if char.isascii() and char.isdigit():
            if start is None:
                start = index
            continue
        if start is None:
            continue
        previous = text[start - 1] if start > 0 else ""
        if (not previous or not (previous.isalnum() or previous == "_")) and not (
            char.isalnum() or char == "_"
        ):
            return text[start:index]
        start = None
    if start is not None:
        previous = text[start - 1] if start > 0 else ""
        if not previous or not (previous.isalnum() or previous == "_"):
            return text[start:]
    return None


def _first_dotted_ascii_version(text: str, *, max_component_digits: int = 4) -> str | None:
    """Return the first bounded ``digits.digits`` run without regex backtracking."""
    index = 0
    while index < len(text):
        if not (text[index].isascii() and text[index].isdigit()):
            index += 1
            continue
        major_start = index
        while index < len(text) and text[index].isascii() and text[index].isdigit():
            index += 1
        major_end = index
        if index >= len(text) or text[index] != ".":
            continue
        index += 1
        minor_start = index
        while index < len(text) and text[index].isascii() and text[index].isdigit():
            index += 1
        if minor_start == index:
            continue
        if (
            major_end - major_start <= max_component_digits
            and index - minor_start <= max_component_digits
        ):
            return text[major_start:index]
    return None


def ecosystem_for_os(os_string: str) -> str | None:
    """Best-effort map a HostInfo.os string to an OSV ecosystem.

    Examples: ``"Ubuntu 22.04"`` -> ``"Ubuntu:22.04"``,
    ``"Debian GNU/Linux 12 (bookworm)"`` -> ``"Debian:12"``.
    Returns ``None`` for distros OSV does not track (e.g. Kali); Kali dpkg
    packages are routed separately through the Debian-origin verifier.
    """
    text = os_string.strip()
    lowered = text.lower()
    if "ubuntu" in lowered and (version := _first_dotted_ascii_version(text)):
        return f"Ubuntu:{version}"
    if "debian" in lowered and (version := _first_standalone_ascii_number(text)):
        return f"Debian:{version}"
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
    *,
    max_findings: int = MAX_FINDINGS,
    max_bytes: int = MAX_FINDING_BYTES,
    limit_state: FindingLimitState | None = None,
) -> list[Vulnerability]:
    """Return vulnerabilities for the packages in ``report``.

    Each package is matched under its own ``Package.ecosystem`` when set,
    otherwise under ``ecosystem`` (the host-derived default). This lets a
    single report mix OS packages (e.g. ``Debian:12``) and language packages
    (e.g. ``PyPI``). Packages with no resolvable ecosystem are skipped.
    """
    findings: list[Vulnerability] = []
    seen: set[tuple[str, str]] = set()
    finding_bytes = 0

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
                    finding = _to_vulnerability(asset, record, vuln_id, fixed)
                    encoded_bytes = len(finding.model_dump_json().encode("utf-8"))
                    if len(findings) >= max_findings or finding_bytes + encoded_bytes > max_bytes:
                        if limit_state is not None:
                            limit_state.mark(
                                "osv_max_findings"
                                if len(findings) >= max_findings
                                else "osv_max_bytes"
                            )
                        logger.warning(
                            "OSV findings truncated at %d item(s) / %d byte(s)",
                            len(findings),
                            finding_bytes,
                        )
                        return findings
                    findings.append(finding)
                    finding_bytes += encoded_bytes
                    break
            except Exception:  # noqa: BLE001 - one bad record must not abort the report
                if limit_state is not None:
                    limit_state.mark_incomplete("osv_record_comparison_failed")
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
        # Attribute image/container package CVEs to their owning image/container so
        # the console can group findings per image. None for host-level packages.
        parent_asset_id=asset.parent_asset_id,
        source=SOURCE,
        evidence=evidence,
        references=references,
    )
