"""Scan orchestration models — fusion-internal API + storage records.

These are **not** agent wire contracts (unlike `AssetReport` / `FlowBatch` /
`GuardEventBatch`): they describe the portal↔fusion trigger/inventory API and
the persisted scan-job / target-registry records. They are intentionally **not**
exported to `schemas-json/` (not registered in `fusion.cli.EXPORTABLE`) and have
no Rust mirror — the portal hand-mirrors them in TypeScript.

Credential safety: a registered `ScanTarget` stores only the credential *mode*
and non-secret references (an `identity_path`). The long-lived secret is a
managed SSH key on the fusion host (installed once via `bootstrap.ensure_key_auth`
from a one-time `ScanTargetInput.password` that is then discarded). No plaintext
password is ever persisted.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .common import StrictModel, Timestamp


class Transport(StrEnum):
    """How fusion reaches a target to deploy the agent."""

    SSH = "ssh"
    WINRM = "winrm"


class CredentialMode(StrEnum):
    """Where the target's durable credential lives on the fusion host."""

    MANAGED_KEY = "managed_key"  # SSH key bootstrapped + stored under ~/.config/scdr/...
    IDENTITY = "identity"  # operator-provided identity file path on the fusion host


class ScanCapability(StrEnum):
    """Which agent capability a scan deploys."""

    HOST = "host"
    FLOW = "flow"
    GUARD = "guard"


class ScanJobState(StrEnum):
    """Lifecycle of a triggered scan job."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ScanTarget(StrictModel):
    """A registered scan target (no secret material)."""

    target_id: str
    name: str
    address: str = Field(description="SSH/WinRM endpoint as user@host")
    port: int = 22
    transport: Transport = Transport.SSH
    credential_mode: CredentialMode = CredentialMode.MANAGED_KEY
    identity_path: str | None = Field(
        default=None, description="server-side key path when credential_mode=identity"
    )
    created_at: Timestamp


class ScanTargetInput(StrictModel):
    """Registration payload. `password` (if any) is one-time bootstrap only."""

    name: str
    address: str
    port: int = 22
    transport: Transport = Transport.SSH
    credential_mode: CredentialMode = CredentialMode.MANAGED_KEY
    identity_path: str | None = None
    password: str | None = Field(
        default=None,
        description="one-time password to bootstrap a managed SSH key; never persisted",
    )


class ScanJobOptions(StrictModel):
    """Per-scan knobs (capability-specific; unused ones ignored)."""

    scan_target: str = Field(default="all", description="host: -t object (host|all|...)")
    malware: bool = Field(default=True, description="host: also run the built-in malware scan")
    pcap: bool = Field(default=False, description="flow: live pcap instead of mock")
    iface: str = "any"
    duration: int = 5
    bpf: str = "tcp or udp or icmp"


class ScanResult(StrictModel):
    """Reference to the artifact a finished scan produced (for portal to fetch)."""

    kind: ScanCapability
    report_id: str | None = None  # host  -> GET /reports/asset-reports/{report_id}
    batch_id: str | None = None  # flow  -> the ingested FlowBatch
    host_id: str | None = None  # guard -> GET /reports/guard-events?host_id=
    pid: str | None = None  # guard daemon PID on the target
    detail: str | None = None


class ScanJob(StrictModel):
    """A triggered scan and its lifecycle/result. Persisted append-only:
    each state transition appends a new row with the same `job_id`; readers take
    the newest (`find_one`) and de-duplicate lists by `job_id`."""

    job_id: str
    target_id: str
    address: str
    capability: ScanCapability
    state: ScanJobState = ScanJobState.PENDING
    options: ScanJobOptions = Field(default_factory=ScanJobOptions)
    created_at: Timestamp
    started_at: Timestamp | None = None
    finished_at: Timestamp | None = None
    result: ScanResult | None = None
    error: str | None = None


class TriggerScanRequest(StrictModel):
    """POST /scans body."""

    target_id: str
    capability: ScanCapability
    options: ScanJobOptions = Field(default_factory=ScanJobOptions)
