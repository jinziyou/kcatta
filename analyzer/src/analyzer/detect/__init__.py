"""Self-implemented vulnerability detection.

Joins the package inventory of an ingested ``AssetReport`` with locally
stored OSV advisory data and emits ``Vulnerability`` findings. No external
scanner (trivy/grype): the OSV parser, the per-ecosystem version comparators
(dpkg / PEP 440 / rpm / apk / SemVer), and range matching are all in this
package.
"""

from .combine import SCANNER_SOURCES, combine_findings, scanner_findings
from .coverage import EcosystemCoverage, PackageCoverage, package_coverage
from .cvss import base_score_from_vector, severity_from_score
from .debian_tracker import (
    DEFAULT_MAX_AGE_SECONDS as DEFAULT_DEBIAN_TRACKER_MAX_AGE_SECONDS,
)
from .debian_tracker import DebianTrackerStore, sync_debian_tracker
from .debversion import dpkg_compare
from .engine import SOURCE, detect_report, ecosystem_for_os, resolve_ecosystem
from .kali import (
    KaliTrackerDetection,
    detect_kali_packages,
    kali_tracker_coverage,
    merge_kali_tracker_status,
)
from .matrix import coverage_matrix
from .osv import OsvRecord, is_version_affected
from .store import OsvStore
from .sync import (
    DEFAULT_OSV_ECOSYSTEMS,
    UNSUPPORTED_COLLECTED_ECOSYSTEMS,
    ecosystem_family,
    read_complete_manifest,
    read_complete_marker,
    sync_ecosystem,
    sync_ecosystem_archive,
    write_complete_manifest,
)
from .versioning import (
    apk_compare,
    comparator_for,
    pep440_compare,
    rpm_compare,
    semver_compare,
)

__all__ = [
    "SOURCE",
    "DEFAULT_OSV_ECOSYSTEMS",
    "DEFAULT_DEBIAN_TRACKER_MAX_AGE_SECONDS",
    "DebianTrackerStore",
    "UNSUPPORTED_COLLECTED_ECOSYSTEMS",
    "OsvRecord",
    "OsvStore",
    "PackageCoverage",
    "KaliTrackerDetection",
    "EcosystemCoverage",
    "SCANNER_SOURCES",
    "apk_compare",
    "base_score_from_vector",
    "comparator_for",
    "combine_findings",
    "coverage_matrix",
    "detect_report",
    "detect_kali_packages",
    "dpkg_compare",
    "ecosystem_for_os",
    "ecosystem_family",
    "is_version_affected",
    "kali_tracker_coverage",
    "merge_kali_tracker_status",
    "pep440_compare",
    "package_coverage",
    "resolve_ecosystem",
    "read_complete_manifest",
    "read_complete_marker",
    "rpm_compare",
    "scanner_findings",
    "semver_compare",
    "severity_from_score",
    "sync_ecosystem",
    "sync_ecosystem_archive",
    "sync_debian_tracker",
    "write_complete_manifest",
]
