"""Shared building blocks for kcatta data contracts.

These types are intentionally minimal and language-neutral so the
same schemas can be consumed (via JSON Schema) by Rust collectors,
TypeScript admin frontends, or any future client.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Severity level of a finding, ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Confidence level in a detection or finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def _ensure_utc(value: datetime) -> datetime:
    """Normalize any datetime to tz-aware UTC.

    A naive datetime is *assumed* to be UTC; an aware one is converted. This
    enforces the contract's "UTC timestamp" promise so stored and compared
    timestamps are never a naive/aware mix (which would raise on comparison).
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


Timestamp = Annotated[
    datetime,
    AfterValidator(_ensure_utc),
    Field(description="UTC timestamp encoded as RFC 3339 / ISO 8601"),
]


class StrictModel(BaseModel):
    """Base class for every wire contract model.

    `extra="forbid"` is deliberate: contracts evolve through explicit
    schema versioning, never by silently accepting unknown fields.
    Upstream agents that send fields outside the schema must fail loudly
    instead of having their data dropped.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )
