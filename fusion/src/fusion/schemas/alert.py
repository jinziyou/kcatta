"""Alerts produced by fusion's correlation engine and consumed by portal."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .common import Severity, StrictModel, Timestamp


class AlertStatus(StrEnum):
    """Lifecycle state of an alert as it is triaged."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class Alert(StrictModel):
    """A correlated security alert linking related assets, vulnerabilities, and flows."""

    alert_id: str
    severity: Severity
    status: AlertStatus = AlertStatus.OPEN
    score: float = Field(ge=0.0, le=100.0, description="Risk score, 0-100")

    title: str
    description: str

    related_asset_ids: list[str] = Field(default_factory=list)
    related_vuln_ids: list[str] = Field(default_factory=list)
    related_flow_ids: list[str] = Field(default_factory=list)

    created_at: Timestamp
    updated_at: Timestamp | None = None
