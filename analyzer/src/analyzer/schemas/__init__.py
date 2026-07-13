"""kcatta data contracts (Pydantic source of truth).

The models defined here form Analyzer's telemetry and analysis contracts:

    agent / exporter --telemetry--> Form --> analyzer
    analyzer --Alert / DetectionResult / AttackPath--> Form --> admin

JSON Schema artifacts derived from these models live under
`analyzer/schemas-json/` and can be consumed by any language (Rust /
TypeScript / ...).
"""

from .alert import Alert, AlertState, AlertStatus, AlertTriageRequest
from .asset import (
    Account,
    Asset,
    Container,
    Credential,
    CredentialKind,
    Image,
    Package,
    Port,
    Service,
)
from .attack import (
    AttackPath,
    AttackPathStep,
    AttackTemplate,
    CapabilityGraph,
    TechniqueCapability,
)
from .common import Confidence, Severity, StrictModel, Timestamp
from .envelope import AssetReport, DetectionResult, HostInfo, TraceBatch
from .guard_event import (
    ActionTaken,
    FileIntegrityEvent,
    FimChange,
    GuardEvent,
    GuardEventBatch,
    IdsEvent,
    MalwareEvent,
    NetworkEvent,
    Outcome,
    ProcessEvent,
)
from .threat import IndicatorType, ThreatMatch
from .trace import FileTraceEvent, ProcessTraceEvent, TraceEvent
from .vulnerability import Vulnerability

__all__ = [
    "Account",
    "ActionTaken",
    "Alert",
    "AlertState",
    "AlertStatus",
    "AlertTriageRequest",
    "Asset",
    "AssetReport",
    "AttackPath",
    "AttackPathStep",
    "AttackTemplate",
    "CapabilityGraph",
    "Confidence",
    "Credential",
    "CredentialKind",
    "DetectionResult",
    "FileIntegrityEvent",
    "FileTraceEvent",
    "FimChange",
    "ProcessTraceEvent",
    "TechniqueCapability",
    "TraceBatch",
    "TraceEvent",
    "GuardEvent",
    "GuardEventBatch",
    "HostInfo",
    "IdsEvent",
    "IndicatorType",
    "MalwareEvent",
    "NetworkEvent",
    "Outcome",
    "Container",
    "Image",
    "Package",
    "Port",
    "ProcessEvent",
    "Service",
    "Severity",
    "StrictModel",
    "ThreatMatch",
    "Timestamp",
    "Vulnerability",
]
