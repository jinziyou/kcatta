"""Threat-intelligence IOC matches attached to events by collector.

These are the result of collector-side *preliminary processing*: each
captured flow is matched against a local IOC feed (malicious IPs,
domains, JA3 fingerprints). Matches ride along on the `TraceEvent` so
analyzer can correlate them into `Alert`s without re-doing the lookup.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .common import CorrelationIdentifier, Severity, StrictModel


class IndicatorType(StrEnum):
    """Type of indicator of compromise that was matched."""

    IP = "ip"
    DOMAIN = "domain"
    JA3 = "ja3"


class ThreatMatch(StrictModel):
    """One IOC hit observed on a flow."""

    indicator: CorrelationIdentifier = Field(
        description="The matched IOC value (IP / domain / JA3 hash)"
    )
    indicator_type: IndicatorType
    category: CorrelationIdentifier = Field(
        description="Threat category, e.g. 'c2', 'malware', 'phishing', 'tor-exit', 'scanner'",
    )
    severity: Severity
    source: CorrelationIdentifier = Field(
        description="Name of the IOC feed that produced the match"
    )
    description: str | None = None
