"""Upload envelopes -- the actual messages exchanged between components.

`AssetReport` and `FlowBatch` are the wire format for scanner / collector
uplink. They wrap one collection cycle's worth of findings with the
metadata needed to attribute, deduplicate, and audit the upload.
"""

from __future__ import annotations

from pydantic import Field

from .asset import Asset
from .common import StrictModel, Timestamp
from .flow import FlowEvent
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
    """scanner -> fusion: one host, one collection cycle."""

    report_id: str
    collected_at: Timestamp
    scanner_version: str

    host: HostInfo
    assets: list[Asset] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class FlowBatch(StrictModel):
    """collector -> fusion: a batch of flow events from one collector instance."""

    batch_id: str
    collected_at: Timestamp
    collector_id: str
    collector_version: str

    flows: list[FlowEvent] = Field(default_factory=list)


class DetectionResult(StrictModel):
    """fusion-derived: vulnerability findings computed for one AssetReport.

    Produced by `fusion.detect` after ingest (or on demand via `/detect`).
    Carries enough provenance to attribute findings back to a host/report.
    """

    report_id: str
    host_id: str
    collected_at: Timestamp = Field(description="When the source AssetReport was collected")
    ecosystem: str = Field(description="OSV ecosystem used for matching, e.g. 'Debian:12'")
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
