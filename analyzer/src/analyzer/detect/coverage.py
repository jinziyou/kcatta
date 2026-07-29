"""Package-level OSV corpus coverage accounting.

An empty lookup is ambiguous: it can mean either "no advisory affects this
package" or "that ecosystem was never synchronized".  This module uses the
atomic ``.complete`` manifest to separate those cases before matching.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..schemas import AssetReport, Package
from .sync import UNSUPPORTED_COLLECTED_ECOSYSTEMS, ecosystem_family


@dataclass(frozen=True)
class PackageCoverage:
    """Packages that can be honestly matched against the loaded OSV corpus."""

    detection_report: AssetReport
    total: int
    resolved: int
    covered: int
    unresolved: int
    uncovered: int
    unsupported: int
    uncovered_ecosystems: tuple[str, ...]
    unsupported_ecosystems: tuple[str, ...]
    ecosystems: tuple[EcosystemCoverage, ...]


@dataclass(frozen=True)
class EcosystemCoverage:
    """Package counts for one exact ecosystem label (or unresolved inventory)."""

    ecosystem: str | None
    total: int
    covered: int
    unresolved: int
    uncovered: int
    unsupported: int


def package_coverage(
    report: AssetReport,
    default_ecosystem: str | None,
    synced_ecosystems: frozenset[str] | None,
) -> PackageCoverage:
    """Classify packages and build a report containing only matchable packages.

    ``synced_ecosystems=None`` means there is no trustworthy manifest.  Matching
    still runs best-effort over every resolvable package, while callers mark the
    result partial because corpus completeness cannot be proven.
    """
    packages = [asset for asset in report.assets if isinstance(asset, Package)]
    covered_packages: list[Package] = []
    unresolved = 0
    uncovered = 0
    unsupported = 0
    uncovered_ecosystems: set[str] = set()
    unsupported_ecosystems: set[str] = set()
    ecosystem_counts: dict[str | None, list[int]] = {}

    def count(ecosystem: str | None, index: int) -> None:
        counts = ecosystem_counts.setdefault(ecosystem, [0, 0, 0, 0, 0])
        counts[0] += 1
        counts[index] += 1

    for package in packages:
        ecosystem = package.ecosystem or default_ecosystem
        if not ecosystem:
            unresolved += 1
            count(None, 2)
            continue
        family = ecosystem_family(ecosystem)
        if family in UNSUPPORTED_COLLECTED_ECOSYSTEMS:
            uncovered += 1
            unsupported += 1
            uncovered_ecosystems.add(ecosystem)
            unsupported_ecosystems.add(ecosystem)
            count(ecosystem, 4)
            continue
        if synced_ecosystems is not None and family not in synced_ecosystems:
            uncovered += 1
            uncovered_ecosystems.add(ecosystem)
            count(ecosystem, 3)
            continue
        covered_packages.append(package)
        count(ecosystem, 1)

    resolved = len(packages) - unresolved
    return PackageCoverage(
        detection_report=report.model_copy(update={"assets": covered_packages}),
        total=len(packages),
        resolved=resolved,
        covered=len(covered_packages),
        unresolved=unresolved,
        uncovered=uncovered,
        unsupported=unsupported,
        uncovered_ecosystems=tuple(sorted(uncovered_ecosystems)),
        unsupported_ecosystems=tuple(sorted(unsupported_ecosystems)),
        ecosystems=tuple(
            EcosystemCoverage(
                ecosystem=ecosystem,
                total=counts[0],
                covered=counts[1],
                unresolved=counts[2],
                uncovered=counts[3] + counts[4],
                unsupported=counts[4],
            )
            for ecosystem, counts in sorted(
                ecosystem_counts.items(), key=lambda item: item[0] or ""
            )
        ),
    )
