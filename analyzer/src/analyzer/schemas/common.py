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

MAX_WIRE_STRING_CHARS = 4096
MAX_WIRE_LIST_ITEMS = 4096
MAX_NESTED_LIST_ITEMS = 256
MAX_THREAT_MATCHES_PER_EVENT = 64
MAX_WIRE_IDENTIFIER_CHARS = MAX_WIRE_STRING_CHARS
MAX_CORRELATION_IDENTIFIER_CHARS = 256

WireIdentifier = Annotated[
    str,
    Field(max_length=MAX_WIRE_IDENTIFIER_CHARS),
]
CorrelationIdentifier = Annotated[
    str,
    Field(max_length=MAX_CORRELATION_IDENTIFIER_CHARS),
]


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

    `extra="ignore"` is deliberate forward-compatibility: a newer agent
    that adds a field the analyzer does not yet know about must NOT have its
    whole upload rejected (422) — that would make a version skew silently
    *drop data* upstream. Unknown fields are dropped on the floor; every
    *declared* field is still strictly typed and validated, so this stays
    "lenient at the boundary, typed internally" rather than "accept anything".

    The same leniency protects the read path: historical records persisted
    before/after a schema change (which may carry fields this version no
    longer declares) re-validate through the ``/reports/*`` ``response_model``
    instead of 500-ing the whole page.
    """

    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
        str_max_length=MAX_WIRE_STRING_CHARS,
    )
