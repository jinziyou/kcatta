"""Self-implemented vulnerability detection.

Joins the package inventory of an ingested ``AssetReport`` with locally
stored OSV advisory data and emits ``Vulnerability`` findings. No external
scanner (trivy/grype): the OSV parser, dpkg version comparator, and range
matching are all in this package.
"""

from .combine import SCANNER_SOURCES, combine_findings, scanner_findings
from .cvss import base_score_from_vector, severity_from_score
from .debversion import dpkg_compare
from .engine import SOURCE, detect_report, ecosystem_for_os, resolve_ecosystem
from .osv import OsvRecord, is_version_affected
from .store import OsvStore
from .sync import sync_ecosystem
from .versioning import (
    apk_compare,
    comparator_for,
    pep440_compare,
    rpm_compare,
    semver_compare,
)

__all__ = [
    "SOURCE",
    "OsvRecord",
    "OsvStore",
    "SCANNER_SOURCES",
    "apk_compare",
    "base_score_from_vector",
    "comparator_for",
    "combine_findings",
    "detect_report",
    "dpkg_compare",
    "ecosystem_for_os",
    "is_version_affected",
    "pep440_compare",
    "resolve_ecosystem",
    "rpm_compare",
    "scanner_findings",
    "semver_compare",
    "severity_from_score",
    "sync_ecosystem",
]
