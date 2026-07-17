"""Scan orchestration models — Form public API + storage records.

These are **not** agent wire contracts (unlike `AssetReport` / `TraceBatch` /
`GuardEventBatch`): they describe the admin↔Form trigger/inventory API and
the persisted scan-job / target-registry records. They are exported from Form
alongside the telemetry schemas and have no Rust mirror.

Credential safety: a registered `ScanTarget` stores only the credential *mode*
and non-secret references (an `identity_path`). The long-lived secret is a
managed SSH key on the Form host (installed once via `bootstrap.ensure_key_auth`
from a one-time `ScanTargetInput.password` that is then discarded). No plaintext
password is ever persisted.
"""

from __future__ import annotations

from enum import StrEnum

from analyzer.schemas.common import StrictModel, Timestamp
from pydantic import Field, model_validator


class Transport(StrEnum):
    """How Form reaches a target to deploy the agent."""

    SSH = "ssh"
    WINRM = "winrm"
    LOCAL = "local"  # the target IS the Form host — run agent-collect-host in-place, no SSH


class CredentialMode(StrEnum):
    """Where the target's durable credential lives on the Form host."""

    MANAGED_KEY = "managed_key"  # SSH key bootstrapped + stored under ~/.config/scdr/...
    IDENTITY = "identity"  # operator-provided identity file path on the Form host
    NONE = "none"  # transport=local — the target is the Form host, no credential at all


class ScanCapability(StrEnum):
    """Which agent capability a scan deploys."""

    HOST = "host"
    TRACE = "trace"
    GUARD = "guard"


class ScanMode(StrEnum):
    """How a detection runs — surfaced explicitly so admin can choose up front.

    Derived from the capability rather than requested independently: ``host`` /
    ``trace`` run once and finish (``oneshot``); ``guard`` deploys a long-lived
    daemon that keeps detecting and streaming events (``resident``).
    """

    ONESHOT = "oneshot"  # 单次：run once, produce an artifact, finish
    RESIDENT = "resident"  # 常驻：a persistent agent daemon that keeps running


# Capabilities whose agent keeps running after the job's start succeeds.
_RESIDENT_CAPABILITIES = frozenset({ScanCapability.GUARD})


def mode_for_capability(capability: ScanCapability) -> ScanMode:
    """Map a capability to its execution mode (guard → resident, else oneshot)."""
    return ScanMode.RESIDENT if capability in _RESIDENT_CAPABILITIES else ScanMode.ONESHOT


class ScanJobState(StrEnum):
    """Lifecycle of a triggered scan job."""

    PENDING = "pending"
    RETRYING = "retrying"
    RUNNING = "running"
    CANCELLING = "cancelling"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DerivedState(StrEnum):
    """Analyzer work that continues after the raw artifact was accepted."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETE = "complete"
    PARTIAL = "partial"


class WindowsDefenderScan(StrEnum):
    """On-demand Microsoft Defender scan requested for a WinRM host job."""

    NONE = "none"
    QUICK = "quick"
    FULL = "full"


class ScanTarget(StrictModel):
    """A registered scan target (no secret material)."""

    target_id: str
    name: str
    address: str = Field(
        description=(
            "SSH/WinRM endpoint as user@host; for transport=local a free label (e.g. localhost)"
        )
    )
    port: int = 22
    transport: Transport = Transport.SSH
    credential_mode: CredentialMode = CredentialMode.MANAGED_KEY
    identity_path: str | None = Field(
        default=None, description="server-side key path when credential_mode=identity"
    )
    canonical_host_id: str | None = Field(
        default=None,
        description=(
            "Stable Analyzer host identity; defaults to target_id and is never taken "
            "from Agent telemetry"
        ),
    )
    created_at: Timestamp

    @model_validator(mode="after")
    def _derive_canonical_host_id(self) -> ScanTarget:
        if self.canonical_host_id is None:
            self.canonical_host_id = self.target_id
        return self


class ScanTargetInput(StrictModel):
    """Registration payload. `password` (if any) is one-time bootstrap only."""

    name: str
    address: str
    port: int = 22
    transport: Transport = Transport.SSH
    credential_mode: CredentialMode = CredentialMode.MANAGED_KEY
    identity_path: str | None = None
    canonical_host_id: str | None = Field(
        default=None,
        description="Optional stable host id; Form assigns target_id when omitted",
    )
    password: str | None = Field(
        default=None,
        description="one-time password to bootstrap a managed SSH key; never persisted",
    )


class ScanJobOptions(StrictModel):
    """Per-scan knobs (capability-specific; unused ones ignored)."""

    scan_target: str = Field(default="all", description="host: upload scope (host|all)")
    malware: bool = Field(default=True, description="host: run configured malware signatures")
    windows_defender_scan: WindowsDefenderScan = Field(
        default=WindowsDefenderScan.QUICK,
        description=(
            "WinRM host: reuse Microsoft Defender (none collects existing history only; "
            "quick/full also starts that on-demand scan)"
        ),
    )
    posture: bool = Field(default=True, description="host: run security-posture checks")
    secrets: bool = Field(default=False, description="host: scan for leaked secret fingerprints")
    pcap: bool = Field(
        default=False,
        description="trace: use custom libpcap build instead of live connection-table capture",
    )
    iface: str = "any"
    duration: int = 5
    bpf: str = "tcp or udp or icmp"
    intel: bool = Field(default=True, description="trace: use Form's managed IOC feed")
    ebpf: bool = Field(default=False, description="trace: collect file/process eBPF events")
    guard_network: bool = Field(default=True, description="guard: enable network IOC and IDS")
    guard_onaccess: bool = Field(
        default=False,
        description="guard: enable on-access malware scanning when the build supports it",
    )


class ScanResult(StrictModel):
    """Reference to the artifact a finished scan produced (for admin to fetch)."""

    kind: ScanCapability
    report_id: str | None = None  # host  -> GET /reports/asset-reports/{report_id}
    batch_id: str | None = None  # flow  -> the ingested TraceBatch
    host_id: str | None = None  # guard -> GET /reports/guard-events?host_id=
    pid: str | None = None  # guard daemon PID on the target
    detail: str | None = None
    derived_state: DerivedState | None = Field(
        default=None,
        description="Analyzer detection/correlation state; absent for resident Guard results",
    )
    derived_records: int = Field(default=0, ge=0)
    derived_truncated: bool = False
    derived_reason: str | None = None
    derived_attempts: int = Field(default=0, ge=0)
    derived_updated_at: Timestamp | None = None


class ScanJob(StrictModel):
    """A triggered scan and its durable worker lifecycle/result.

    Public job data deliberately excludes the worker's lease token and fencing
    epoch. Those coordination fields stay in Form's private job repository;
    Admin only sees useful scheduling state and attempt metadata.
    """

    job_id: str
    target_id: str
    address: str
    capability: ScanCapability
    # Execution mode, derived from capability when absent (so historical rows
    # persisted before this field existed still read back with a correct mode).
    mode: ScanMode | None = None
    state: ScanJobState = ScanJobState.PENDING
    options: ScanJobOptions = Field(default_factory=ScanJobOptions)
    created_at: Timestamp
    updated_at: Timestamp | None = None
    available_at: Timestamp | None = Field(
        default=None,
        description="Earliest time the durable worker may claim a pending/retrying job",
    )
    started_at: Timestamp | None = None
    finished_at: Timestamp | None = None
    cancel_requested_at: Timestamp | None = None
    attempt: int = Field(default=0, ge=0, description="Number of execution attempts claimed")
    max_attempts: int = Field(default=3, ge=1, le=20)
    result: ScanResult | None = None
    error: str | None = None

    @model_validator(mode="after")
    def _derive_mode(self) -> ScanJob:
        if self.mode is None:
            self.mode = mode_for_capability(self.capability)
        if self.updated_at is None:
            self.updated_at = self.created_at
        if self.available_at is None and self.state in {
            ScanJobState.PENDING,
            ScanJobState.RETRYING,
        }:
            self.available_at = self.created_at
        return self


class TriggerScanRequest(StrictModel):
    """POST /scans body."""

    target_id: str
    capability: ScanCapability
    options: ScanJobOptions = Field(default_factory=ScanJobOptions)


# ----------------------------------------------------- access-credential mgmt
#
# A "credential" here is the *durable* access secret a registered target uses —
# i.e. a tool-managed SSH key on the Form host, or an operator-provided
# identity-file path. These are derived (read) from the target registry, not a
# separate store: there is still no plaintext password persisted by Form.


class CredentialInfo(StrictModel):
    """A durable access credential, summarized for management (no secret material).

    Derived from registered targets: managed keys are grouped by their logical
    transport + ``user@host:port`` identity, so IDs remain stable if Form's
    configuration root moves. ``target_ids`` lists every target that shares it.
    """

    credential_id: str  # stable id derived from logical endpoint (cred-<hash>)
    credential_mode: CredentialMode  # managed_key | identity (none/local have no credential)
    transport: Transport = Transport.SSH  # ssh → managed key; winrm → managed client cert
    address: str = Field(description="user@host this credential authenticates to")
    port: int = 22
    key_path: str = Field(description="server-side path of the key/cert on the Form host")
    exists: bool = Field(description="whether the key/cert file is present on the Form host")
    fingerprint: str | None = Field(
        default=None, description="SHA256 fingerprint of the public key, when resolvable"
    )
    target_ids: list[str] = Field(default_factory=list)
    target_names: list[str] = Field(default_factory=list)


class CredentialActionRequest(StrictModel):
    """Body for rotate/revoke. ``password`` is a one-time SSH fallback, never persisted."""

    password: str | None = Field(
        default=None,
        description=(
            "one-time password used only when the current managed key can no longer "
            "authenticate (rotate/revoke fallback); never persisted"
        ),
    )


class CredentialTestResult(StrictModel):
    """Result of probing whether a credential can still authenticate."""

    ok: bool
    detail: str = ""


class CredentialRevokeResult(StrictModel):
    """Result of revoking a managed key (remote authorized_keys + local key files)."""

    revoked: bool = Field(description="True if a key line was removed from the target")
    key_deleted: bool = Field(default=False, description="True if local key files were removed")
    detail: str = ""


# --------------------------------------------------------- guard (resident) lifecycle


class GuardLifecycleStatus(StrictModel):
    """Liveness of a target's resident guard daemon (for the 常驻 management view)."""

    target_id: str
    address: str
    alive: bool
    supervisor: str = Field(description="systemd | process | unknown")
    pid: str | None = None
    detail: str = ""
