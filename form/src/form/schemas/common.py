"""Shared building blocks for cyber-posture data contracts.

These types are intentionally minimal and language-neutral so the
same schemas can be consumed (via JSON Schema) by Rust collectors,
TypeScript portals, or any future client.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


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


Timestamp = Annotated[
    datetime,
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
