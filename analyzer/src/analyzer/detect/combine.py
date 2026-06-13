"""Merge OSV detection output with scanner-native findings (malware hits)."""

from __future__ import annotations

from ..schemas import AssetReport, Vulnerability

# Sources copied verbatim from AssetReport.vulnerabilities into DetectionResult.
# `kcatta-malware` is the agent's built-in signature scanner; `clamav` is kept
# for backward compatibility with reports produced before the engine switch.
SCANNER_SOURCES = frozenset({"kcatta-malware", "clamav"})


def scanner_findings(report: AssetReport) -> list[Vulnerability]:
    """Malware / virus hits already attached to the report by scanner."""
    return [v for v in report.vulnerabilities if v.source in SCANNER_SOURCES]


def combine_findings(
    osv: list[Vulnerability],
    scanner: list[Vulnerability],
) -> list[Vulnerability]:
    """OSV CVE findings first, then scanner-native hits."""
    return osv + scanner
