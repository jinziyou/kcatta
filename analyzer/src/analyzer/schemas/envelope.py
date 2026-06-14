"""Upload envelopes -- the actual messages exchanged between components.

`AssetReport` and `TraceBatch` are the wire format for scanner / collector
uplink. They wrap one collection cycle's worth of findings with the
metadata needed to attribute, deduplicate, and audit the upload.
"""

from __future__ import annotations

from pydantic import Field

from .asset import Asset
from .common import StrictModel, Timestamp
from .trace import FileTraceEvent, ProcessTraceEvent, TraceEvent
from .vulnerability import Vulnerability


class HostInfo(StrictModel):
    """Identity and network metadata of the host an upload originates from."""

    host_id: str
    hostname: str
    os: str = Field(description="OS family + version, e.g. 'Ubuntu 22.04'")
    kernel: str | None = None
    arch: str | None = None
    ip_addrs: list[str] = Field(default_factory=list)
    mac_addrs: list[str] = Field(default_factory=list)
    boot_time: Timestamp | None = None


class AssetReport(StrictModel):
    """scanner -> analyzer: one host, one collection cycle."""

    report_id: str
    collected_at: Timestamp
    scanner_version: str

    host: HostInfo
    assets: list[Asset] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class TraceBatch(StrictModel):
    """collector -> analyzer: a batch of trace events from one collector instance.

    Carries three homogeneous streams from one eBPF collection cycle: network
    traces (5-tuple flows), file operations, and process lifecycle events.
    """

    batch_id: str
    collected_at: Timestamp
    collector_id: str
    collector_version: str

    events: list[TraceEvent] = Field(
        default_factory=list, description="Network traces (5-tuple flows + IOC matches)."
    )
    file_events: list[FileTraceEvent] = Field(
        default_factory=list, description="File-system operations observed by the eBPF tracer."
    )
    process_events: list[ProcessTraceEvent] = Field(
        default_factory=list, description="Process exec/exit events observed by the eBPF tracer."
    )


class DetectionResult(StrictModel):
    """analyzer-derived: vulnerability findings computed for one AssetReport.

    Produced by `analyzer.detect` after ingest (or on demand via `/detect`).
    Carries enough provenance to attribute findings back to a host/report.
    """

    report_id: str
    host_id: str
    collected_at: Timestamp = Field(description="When the source AssetReport was collected")
    ecosystem: str = Field(description="OSV ecosystem used for matching, e.g. 'Debian:12'")
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
