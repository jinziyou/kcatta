"""kcatta data contracts (Pydantic source of truth).

The models defined here form the wire contracts between kcatta's
components (agent / analyzer / admin) and the external red-team exporter:

    agentd host    --AssetReport------>  analyzer
    agentd trace    --TraceBatch-------->  analyzer
    agentd guard   --GuardEventBatch->   analyzer
    red exporter  --CapabilityGraph->   analyzer
    analyzer        --Alert / DetectionResult / AttackPath-->  admin

JSON Schema artifacts derived from these models live under
`analyzer/schemas-json/` and can be consumed by any language (Rust /
TypeScript / ...).
"""

from .alert import Alert, AlertStatus
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
from .trace import FileTraceEvent, ProcessTraceEvent, TraceEvent
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
    # Scan orchestration (analyzer-internal; not exported to schemas-json)
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
