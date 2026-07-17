"""Normalized Microsoft Defender Vulnerability Management snapshots."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .common import (
    MAX_NESTED_LIST_ITEMS,
    MAX_WIRE_LIST_ITEMS,
    CorrelationIdentifier,
    Severity,
    StrictModel,
    Timestamp,
    WireIdentifier,
)


class MdvmSoftwareVulnerability(StrictModel):
    """One active CVE/software combination from the MDVM assessment."""

    record_id: WireIdentifier
    cve_id: CorrelationIdentifier
    software_vendor: str
    software_name: str
    software_version: str
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    exploitability_level: str | None = None
    recommended_security_update: str | None = None
    recommended_security_update_id: WireIdentifier | None = None
    recommended_security_update_url: str | None = None
    recommendation_reference: WireIdentifier | None = None
    security_update_available: bool | None = None
    first_seen_at: Timestamp | None = None
    last_seen_at: Timestamp | None = None
    last_event_at: Timestamp | None = None
    rbac_group_id: WireIdentifier | None = None
    rbac_group_name: str | None = None
    disk_paths: list[str] = Field(default_factory=list, max_length=64)
    registry_paths: list[str] = Field(default_factory=list, max_length=64)
    evidence_truncated: bool = False


class MdvmDeviceSnapshot(StrictModel):
    """A complete bounded part of the current active MDVM findings for one device."""

    report_id: CorrelationIdentifier
    device_id: WireIdentifier
    host_id: CorrelationIdentifier
    device_name: WireIdentifier
    os_platform: str
    os_version: str | None = None
    os_architecture: str | None = None
    observed_at: Timestamp
    part_index: int = Field(default=1, ge=1)
    part_total: int = Field(default=1, ge=1)
    vulnerabilities: list[MdvmSoftwareVulnerability] = Field(
        default_factory=list,
        max_length=MAX_WIRE_LIST_ITEMS,
    )


class MdvmVulnerabilityBatch(StrictModel):
    """Deterministic Analyzer handoff from one baseline or delta materialization."""

    batch_id: CorrelationIdentifier
    collected_at: Timestamp
    tenant_id: WireIdentifier
    mode: Literal["baseline", "delta"]
    snapshots: list[MdvmDeviceSnapshot] = Field(
        default_factory=list,
        max_length=MAX_NESTED_LIST_ITEMS,
    )
