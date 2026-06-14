"""Real-time protection (guard) events reported by `agent-guard`.

Unlike `AssetReport` (a point-in-time host snapshot) and `TraceBatch` (observed
events), a `GuardEventBatch` carries a stream of **live detections plus the
response action the endpoint took** — the wire format for the guard daemon's
detect → respond → report pipeline.

`GuardEvent` is a discriminated union keyed on `kind`. Adding a new event type
means: (1) create a new `_GuardEventBase` subclass with a unique
`kind: Literal["..."]`, (2) add it to the `GuardEvent` union, (3) bump the
contract version.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field

from .common import Severity, StrictModel, Timestamp
from .threat import IndicatorType


class ActionTaken(StrEnum):
    """The response action the guard attempted for a detection.

    `none` / `logged` are non-destructive (detection-only / monitor mode); the
    rest are active responses gated behind enforce mode + per-action policy.
    """

    NONE = "none"
    LOGGED = "logged"
    QUARANTINED = "quarantined"
    BLOCKED_OPEN = "blocked_open"
    BLOCKED_CONNECTION = "blocked_connection"
    KILLED = "killed"
    SUSPENDED = "suspended"


class Outcome(StrEnum):
    """Result of an attempted response action."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"


class FimChange(StrEnum):
    """Kind of file-integrity change observed."""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    METADATA = "metadata"


GuardProto = Literal["tcp", "udp", "icmp", "other"]
"""Transport class for network / IDS events (mirrors `TraceProto`)."""


class _GuardEventBase(StrictModel):
    """Fields common to every guard event."""

    event_id: str = Field(description="Stable id for this event within the batch")
    timestamp: Timestamp
    severity: Severity
    host_id: str
    action_taken: ActionTaken
    outcome: Outcome


class FileIntegrityEvent(_GuardEventBase):
    """A monitored file changed (FIM)."""

    kind: Literal["fim"] = "fim"
    path: str
    change_type: FimChange
    hash_before: str | None = Field(default=None, description="SHA-256 before the change, if known")
    hash_after: str | None = Field(default=None, description="SHA-256 after the change, if known")


class MalwareEvent(_GuardEventBase):
    """An on-access scan flagged a file."""

    kind: Literal["malware"] = "malware"
    path: str
    signature: str = Field(description="Detection / signature name, e.g. 'EICAR-Test-File'")
    source: str = Field(description="Scanner that produced the hit, e.g. 'kcatta-malware'")
    process_id: int | None = Field(default=None, description="PID that triggered the open")


class ProcessEvent(_GuardEventBase):
    """A suspicious process / behavior was observed."""

    kind: Literal["process"] = "process"
    pid: int
    process_name: str
    behavior: str = Field(
        description="Behavior class, e.g. 'privilege_escalation', 'exe_deleted_running'",
    )
    rule_id: str = Field(description="Identifier of the behavior rule that fired")
    evidence: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None


class NetworkEvent(_GuardEventBase):
    """A live connection matched a threat-intel IOC."""

    kind: Literal["network"] = "network"
    proto: GuardProto
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    indicator: str = Field(description="The matched IOC value (IP / domain / JA3)")
    indicator_type: IndicatorType
    category: str = Field(description="IOC category, e.g. 'c2', 'malware'")
    source: str = Field(description="IOC feed that produced the match")


class IdsEvent(_GuardEventBase):
    """A packet / flow matched an IDS signature."""

    kind: Literal["ids"] = "ids"
    signature_id: str = Field(description="Rule SID")
    signature_name: str
    proto: GuardProto
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None


GuardEvent = Annotated[
    FileIntegrityEvent | MalwareEvent | ProcessEvent | NetworkEvent | IdsEvent,
    Field(discriminator="kind"),
]


class GuardEventBatch(StrictModel):
    """agent-guard -> analyzer: a batch of real-time protection events from one host."""

    batch_id: str
    collected_at: Timestamp
    host_id: str
    agent_version: str

    events: list[GuardEvent] = Field(default_factory=list)
