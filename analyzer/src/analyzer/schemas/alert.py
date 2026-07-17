"""Alerts produced by analyzer's correlation engine and consumed by admin."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from .common import (
    MAX_NESTED_LIST_ITEMS,
    CorrelationIdentifier,
    Severity,
    StrictModel,
    Timestamp,
)


class AlertStatus(StrEnum):
    """Lifecycle state of an alert as it is triaged."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class Alert(StrictModel):
    """A correlated security alert linking related assets, vulnerabilities, and events."""

    alert_id: CorrelationIdentifier
    # Content-derived stable identity (sha1 of the indicator/host tuple, with NO
    # batch_id). Every per-batch occurrence of the same finding shares one
    # alert_key — it is what triage state and de-duplication key on, so a
    # persistent indicator is one triageable alert rather than one-per-batch.
    # Optional for backward compatibility with alerts persisted before this field.
    alert_key: CorrelationIdentifier | None = None
    severity: Severity
    status: AlertStatus = AlertStatus.OPEN
    score: float = Field(ge=0.0, le=100.0, description="Risk score, 0-100")

    title: str
    description: str

    related_asset_ids: list[CorrelationIdentifier] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    related_vuln_ids: list[CorrelationIdentifier] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    related_trace_ids: list[CorrelationIdentifier] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    evidence_truncated: bool = Field(
        default=False,
        description=(
            "True when lifecycle aggregation found more related evidence IDs than "
            "the bounded wire lists can retain."
        ),
    )

    # Triage overlay, populated by the read layer from the latest AlertState for
    # this alert_key (the stored correlation Alert never carries these itself).
    assignee: str | None = None
    note: str | None = None
    suppressed: bool = False

    # Aggregation across the occurrences sharing this alert_key within the read
    # window: how many times it fired and when it was last seen.
    occurrence_count: int = Field(default=1, ge=1)
    last_seen: Timestamp | None = None

    created_at: Timestamp
    updated_at: Timestamp | None = None


class AlertState(StrictModel):
    """A triage-state snapshot for one ``alert_key`` (append-only; newest wins).

    Analyzer-internal: persisted in its own store and merged onto :class:`Alert`
    by the read layer, so it is **not** exported to ``schemas-json`` (Form only
    receives the merged Alert).

    A full snapshot rather than a delta: the triage endpoint reads the current
    state, applies the partial :class:`AlertTriageRequest`, and appends a new
    complete snapshot, so "current state" is a single newest-record lookup.
    """

    alert_key: CorrelationIdentifier
    status: AlertStatus
    assignee: str | None = None
    note: str | None = None
    suppressed: bool = False
    # Who performed the triage. Under shared-token auth this is best-effort
    # provenance (e.g. "shared-token"); a real principal awaits the identity layer.
    actor: str | None = None
    updated_at: Timestamp


class AlertTriageRequest(StrictModel):
    """A partial triage update posted by the console.

    Every field is optional (a delta over the current state) but at least one
    must be set. ``None`` means "leave unchanged"; for the text fields an empty
    string is a deliberate clear. Analyzer-internal (a request body), not exported.
    """

    status: AlertStatus | None = None
    assignee: str | None = None
    note: str | None = None
    suppressed: bool | None = None

    @model_validator(mode="after")
    def _require_one_field(self) -> AlertTriageRequest:
        if (
            self.status is None
            and self.assignee is None
            and self.note is None
            and self.suppressed is None
        ):
            raise ValueError("triage request must set at least one field")
        return self
