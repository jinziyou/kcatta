"""cyber-posture data contracts (Pydantic source of truth).

The models defined here form the wire contract between the four
components of cyber-posture:

    scanner   --AssetReport-->  form
    collector --FlowBatch--->   form
    form      --Alert------->   portal

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
from .common import Confidence, Severity, StrictModel, Timestamp
from .envelope import AssetReport, DetectionResult, FlowBatch, HostInfo
from .flow import FlowEvent
from .vulnerability import Vulnerability

__all__ = [
    "Account",
    "Alert",
    "AlertStatus",
    "Asset",
    "AssetReport",
    "Confidence",
    "Credential",
    "CredentialKind",
    "DetectionResult",
    "FlowBatch",
    "FlowEvent",
    "HostInfo",
    "Package",
    "Port",
    "Service",
    "Severity",
    "StrictModel",
    "Timestamp",
    "Vulnerability",
]
