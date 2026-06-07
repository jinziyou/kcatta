"""posture data contracts (Pydantic source of truth).

The models defined here form the wire contract between the four
components of posture:

    fusion-host  --AssetReport-->  form
    fusion-flow  --FlowBatch--->   form
    form        --Alert------->   portal

JSON Schema artifacts derived from these models live under
`form/schemas-json/` and can be consumed by any language (Rust /
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
from .threat import IndicatorType, ThreatMatch
from .vulnerability import Vulnerability

__all__ = [
    "Account",
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
    "TechniqueCapability",
    "FlowBatch",
    "FlowEvent",
    "HostInfo",
    "IndicatorType",
    "Package",
    "Port",
    "Service",
    "Severity",
    "StrictModel",
    "ThreatMatch",
    "Timestamp",
    "Vulnerability",
]
