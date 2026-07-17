"""Normalized read-only Microsoft Defender for Endpoint cloud telemetry."""

from __future__ import annotations

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


class MdeEvidence(StrictModel):
    """Bounded, allow-listed evidence copied from a Microsoft Graph alert."""

    evidence_type: str
    created_at: Timestamp | None = None
    verdict: str | None = None
    remediation_status: str | None = None
    roles: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)
    summary: str | None = None

    mde_device_id: WireIdentifier | None = None
    azure_ad_device_id: WireIdentifier | None = None
    device_dns_name: str | None = None
    hostname: str | None = None
    os_platform: str | None = None
    os_build: str | None = None
    ip_addresses: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)
    canonical_host_id: CorrelationIdentifier | None = None


class MdeAlert(StrictModel):
    """One Microsoft Graph security alert normalized for durable ingest."""

    alert_id: WireIdentifier
    provider_alert_id: WireIdentifier | None = None
    incident_id: WireIdentifier | None = None
    title: str
    description: str = ""
    severity: Severity
    provider_status: str
    classification: str | None = None
    determination: str | None = None
    service_source: str | None = None
    product_name: str | None = None
    detection_source: str | None = None
    created_at: Timestamp
    first_activity_at: Timestamp | None = None
    last_activity_at: Timestamp | None = None
    last_updated_at: Timestamp
    resolved_at: Timestamp | None = None
    portal_url: str | None = None
    mitre_techniques: list[str] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    related_asset_ids: list[CorrelationIdentifier] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    evidence: list[MdeEvidence] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    evidence_truncated: bool = False


class MdeIncident(StrictModel):
    """One Microsoft Graph security incident and its normalized relationships."""

    incident_id: WireIdentifier
    display_name: str
    description: str = ""
    severity: Severity
    provider_status: str
    classification: str | None = None
    determination: str | None = None
    created_at: Timestamp
    last_updated_at: Timestamp
    resolved_at: Timestamp | None = None
    portal_url: str | None = None
    alert_ids: list[WireIdentifier] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    related_asset_ids: list[CorrelationIdentifier] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    relationships_truncated: bool = False


class MdeSecurityBatch(StrictModel):
    """A deterministic chunk from one incremental MDE cloud synchronization."""

    batch_id: CorrelationIdentifier
    collected_at: Timestamp
    tenant_id: WireIdentifier
    query_started_at: Timestamp
    alerts: list[MdeAlert] = Field(default_factory=list, max_length=MAX_WIRE_LIST_ITEMS)
    incidents: list[MdeIncident] = Field(default_factory=list, max_length=MAX_WIRE_LIST_ITEMS)

