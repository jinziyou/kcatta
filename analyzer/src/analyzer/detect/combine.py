"""Merge OSV detection output with scanner-native findings (malware hits)."""

from __future__ import annotations

from itertools import chain

from ..schemas import AssetReport, Vulnerability
from .limits import MAX_FINDING_BYTES, MAX_FINDINGS, FindingLimitState

# Sources copied verbatim from AssetReport.vulnerabilities into DetectionResult.
# `kcatta-malware` is the agent's built-in signature scanner; `posture` is its
# host-misconfig checks (sshd_config / shadow / SUID); `secret` is its
# secret-leak scan (private keys, cloud/provider tokens); `clamav` is kept for
# backward compatibility with reports produced before the engine switch.
SCANNER_SOURCES = frozenset(
    {
        "kcatta-malware",
        "posture",
        "secret",
        "clamav",
        "microsoft-defender",
        "microsoft-defender-event",
    }
)


def scanner_findings(
    report: AssetReport,
    *,
    max_findings: int = MAX_FINDINGS,
    max_bytes: int = MAX_FINDING_BYTES,
    limit_state: FindingLimitState | None = None,
) -> list[Vulnerability]:
    """Agent-attached findings (malware hits, posture misconfig) to surface as-is."""
    findings: list[Vulnerability] = []
    consumed = 0
    for finding in report.vulnerabilities:
        if finding.source not in SCANNER_SOURCES:
            if limit_state is not None:
                limit_state.mark_incomplete("untrusted_scanner_source")
            continue
        encoded_bytes = len(finding.model_dump_json().encode("utf-8"))
        if len(findings) >= max_findings or consumed + encoded_bytes > max_bytes:
            if limit_state is not None:
                limit_state.mark(
                    "scanner_max_findings" if len(findings) >= max_findings else "scanner_max_bytes"
                )
            break
        findings.append(finding)
        consumed += encoded_bytes
    return findings


def combine_findings(
    osv: list[Vulnerability],
    scanner: list[Vulnerability],
    *,
    max_findings: int = MAX_FINDINGS,
    max_bytes: int = MAX_FINDING_BYTES,
    limit_state: FindingLimitState | None = None,
) -> list[Vulnerability]:
    """OSV CVE findings first, then scanner-native hits."""
    combined: list[Vulnerability] = []
    consumed = 0
    for finding in chain(osv, scanner):
        encoded_bytes = len(finding.model_dump_json().encode("utf-8"))
        if len(combined) >= max_findings or consumed + encoded_bytes > max_bytes:
            if limit_state is not None:
                limit_state.mark(
                    "combined_max_findings"
                    if len(combined) >= max_findings
                    else "combined_max_bytes"
                )
            break
        combined.append(finding)
        consumed += encoded_bytes
    return combined
