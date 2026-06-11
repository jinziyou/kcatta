"""posture data contracts (Pydantic source of truth).

The models defined here form the wire contracts between posture's
components (agent / fusion / portal) and the external red-team exporter:

    agent host    --AssetReport------>  fusion
    agent flow    --FlowBatch-------->  fusion
    agent guard   --GuardEventBatch->   fusion
    red exporter  --CapabilityGraph->   fusion
    fusion        --Alert / DetectionResult / AttackPath-->  portal

JSON Schema artifacts derived from these models live under
`fusion/schemas-json/` and can be consumed by any language (Rust /
TypeScript / ...).
"""

from .alert import Alert, AlertStatus
from .asset import (
    Account,
    Asset,
    Credential,
    CredentialKind,
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
from .envelope import AssetReport, DetectionResult, FlowBatch, HostInfo
from .flow import FlowEvent
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
from .scan import (
    CredentialMode,
    ScanCapability,
    ScanJob,
    ScanJobOptions,
    ScanJobState,
    ScanResult,
    ScanTarget,
    ScanTargetInput,
    Transport,
    TriggerScanRequest,
)
from .threat import IndicatorType, ThreatMatch
from .vulnerability import Vulnerability

__all__ = [
    "Account",
    "ActionTaken",
    "Alert",
    "AlertStatus",
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
    "FimChange",
    "TechniqueCapability",
    "FlowBatch",
    "FlowEvent",
    "GuardEvent",
    "GuardEventBatch",
    "HostInfo",
    "IdsEvent",
    "IndicatorType",
    "MalwareEvent",
    "NetworkEvent",
    "Outcome",
    "Package",
    "Port",
    "ProcessEvent",
    "Service",
    "Severity",
    "StrictModel",
    "ThreatMatch",
    "Timestamp",
    "Vulnerability",
    # Scan orchestration (fusion-internal; not exported to schemas-json)
    "CredentialMode",
    "ScanCapability",
    "ScanJob",
    "ScanJobOptions",
    "ScanJobState",
    "ScanResult",
    "ScanTarget",
    "ScanTargetInput",
    "Transport",
    "TriggerScanRequest",
]
