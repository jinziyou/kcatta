"""Upload envelopes -- the actual messages exchanged between components.

`AssetReport` and `TraceBatch` are the wire format for scanner / collector
uplink. They wrap one collection cycle's worth of findings with the
metadata needed to attribute, deduplicate, and audit the upload.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .asset import Asset
from .common import (
    MAX_NESTED_LIST_ITEMS,
    MAX_WIRE_LIST_ITEMS,
    CorrelationIdentifier,
    StrictModel,
    Timestamp,
    WireIdentifier,
)
from .trace import FileTraceEvent, ProcessTraceEvent, TraceEvent
from .vulnerability import Vulnerability


class HostInfo(StrictModel):
    """Identity and network metadata of the host an upload originates from."""

    host_id: CorrelationIdentifier
    hostname: WireIdentifier
    os: str = Field(description="OS family + version, e.g. 'Ubuntu 22.04'")
    kernel: str | None = None
    arch: str | None = None
    ip_addrs: list[CorrelationIdentifier] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    mac_addrs: list[CorrelationIdentifier] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    boot_time: Timestamp | None = None


class DetectorKind(StrEnum):
    """Detection engines whose execution/coverage is surfaced to operators."""

    OSV = "osv"
    DEBIAN_TRACKER = "debian_tracker"
    DEFENDER = "defender"
    MALWARE = "malware"
    POSTURE = "posture"
    SECRET = "secret"


class DetectorRunStatus(StrEnum):
    """Producer-observed outcome for one enabled detector."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class DetectorRun(StrictModel):
    """Agent-declared execution evidence; absence differs from a zero finding run."""

    detector: DetectorKind
    status: DetectorRunStatus = DetectorRunStatus.COMPLETE
    finding_count: int = Field(default=0, ge=0)
    reason: str | None = None


class AssetReport(StrictModel):
    """agentd -> Form -> analyzer: one host, one collection cycle."""

    report_id: CorrelationIdentifier
    collected_at: Timestamp
    scanner_version: CorrelationIdentifier
    source_agent_id: CorrelationIdentifier | None = Field(
        default=None,
        description="Authenticated Agent identity injected by Form; never trusted from payload",
    )
    source_target_id: CorrelationIdentifier | None = Field(
        default=None,
        description=(
            "Form-owned registered target attribution; absent only for unbound legacy telemetry"
        ),
    )

    host: HostInfo
    assets: list[Asset] = Field(default_factory=list, max_length=MAX_WIRE_LIST_ITEMS)
    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list, max_length=MAX_WIRE_LIST_ITEMS
    )
    detector_runs: list[DetectorRun] | None = Field(
        default=None,
        max_length=32,
        description=(
            "Detectors explicitly executed by the producer. null means legacy/unknown; "
            "an empty list means the producer confirms none were enabled."
        ),
    )


class TraceBatch(StrictModel):
    """agentd -> Form -> analyzer: trace events from one collector instance.

    Carries three homogeneous streams from one eBPF collection cycle: network
    traces (5-tuple flows), file operations, and process lifecycle events.
    """

    batch_id: CorrelationIdentifier
    collected_at: Timestamp
    collector_id: CorrelationIdentifier
    collector_version: CorrelationIdentifier
    source_agent_id: CorrelationIdentifier | None = Field(
        default=None,
        description="Authenticated Agent identity injected by Form; never trusted from payload",
    )
    source_target_id: CorrelationIdentifier | None = Field(
        default=None,
        description=(
            "Form-owned registered target attribution; absent only for unbound legacy telemetry"
        ),
    )

    events: list[TraceEvent] = Field(
        default_factory=list,
        max_length=MAX_WIRE_LIST_ITEMS,
        description="Network traces (5-tuple flows + IOC matches).",
    )
    file_events: list[FileTraceEvent] = Field(
        default_factory=list,
        max_length=MAX_WIRE_LIST_ITEMS,
        description="File-system operations observed by the eBPF tracer.",
    )
    process_events: list[ProcessTraceEvent] = Field(
        default_factory=list,
        max_length=MAX_WIRE_LIST_ITEMS,
        description="Process exec/exit events observed by the eBPF tracer.",
    )


class DetectionStatus(StrEnum):
    """Coverage state for Analyzer's vulnerability-detection pass."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    DISABLED = "disabled"
    FAILED = "failed"


class CoverageStatus(StrEnum):
    """Operator-facing status of one detector/scope in the coverage matrix."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    DISABLED = "disabled"
    FAILED = "failed"
    UNKNOWN = "unknown"


class DetectionCoverage(StrictModel):
    """One detector and optional ecosystem scope, with explicit zero-find evidence."""

    detector: DetectorKind
    ecosystem: CorrelationIdentifier | None = None
    status: CoverageStatus
    scanned_count: int = Field(default=0, ge=0)
    skipped_count: int = Field(default=0, ge=0)
    finding_count: int = Field(default=0, ge=0)
    reason: str | None = None


class DetectionResult(StrictModel):
    """analyzer-derived: vulnerability findings computed for one AssetReport.

    Produced by `analyzer.detect` after ingest (or on demand via `/detect`).
    Carries enough provenance to attribute findings back to a host/report.
    """

    report_id: CorrelationIdentifier
    host_id: CorrelationIdentifier
    collected_at: Timestamp = Field(description="When the source AssetReport was collected")
    ecosystem: CorrelationIdentifier = Field(
        description="OSV ecosystem used for matching, e.g. 'Debian:12'"
    )
    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list, max_length=MAX_WIRE_LIST_ITEMS
    )
    detection_status: DetectionStatus = Field(
        default=DetectionStatus.PARTIAL,
        description=(
            "Whether Analyzer completed vulnerability matching. A complete empty "
            "result is a verified zero-finding pass; disabled/partial/failed must "
            "not be presented as clean. The conservative partial default keeps "
            "pre-coverage historical records from being upgraded to complete."
        ),
    )
    status_reason: str | None = Field(
        default="legacy_coverage_unknown",
        description="Stable operator-facing reason when coverage is not complete.",
    )
    scanned_package_count: int = Field(default=0, ge=0)
    unresolved_package_count: int = Field(
        default=0,
        ge=0,
        description="Packages skipped because no OSV ecosystem could be resolved.",
    )
    uncovered_package_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Packages with a resolved ecosystem that was absent from the atomic "
            "OSV sync manifest and therefore was not matched."
        ),
    )
    truncated: bool = Field(
        default=False,
        description="True when generation limits omitted one or more findings.",
    )
    truncation_reason: str | None = Field(
        default=None,
        description="Which item/byte ceiling caused findings to be omitted.",
    )
    coverage: list[DetectionCoverage] = Field(
        default_factory=list,
        max_length=MAX_NESTED_LIST_ITEMS,
        description="Per-detector and per-ecosystem coverage; empty on legacy rows.",
    )
