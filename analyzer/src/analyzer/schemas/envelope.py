"""Upload envelopes -- the actual messages exchanged between components.

`AssetReport` and `TraceBatch` are the wire format for scanner / collector
uplink. They wrap one collection cycle's worth of findings with the
metadata needed to attribute, deduplicate, and audit the upload.
"""

from __future__ import annotations

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
