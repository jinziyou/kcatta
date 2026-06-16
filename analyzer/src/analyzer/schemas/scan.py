"""Scan orchestration models — analyzer-internal API + storage records.

These are **not** agent wire contracts (unlike `AssetReport` / `TraceBatch` /
`GuardEventBatch`): they describe the admin↔analyzer trigger/inventory API and
the persisted scan-job / target-registry records. They are intentionally **not**
exported to `schemas-json/` (not registered in `analyzer.cli.EXPORTABLE`) and have
no Rust mirror — the admin hand-mirrors them in TypeScript.

Credential safety: a registered `ScanTarget` stores only the credential *mode*
and non-secret references (an `identity_path`). The long-lived secret is a
managed SSH key on the analyzer host (installed once via `bootstrap.ensure_key_auth`
from a one-time `ScanTargetInput.password` that is then discarded). No plaintext
password is ever persisted.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from .common import StrictModel, Timestamp


class Transport(StrEnum):
    """How analyzer reaches a target to deploy the agent."""

    SSH = "ssh"
    WINRM = "winrm"
    LOCAL = "local"  # the target IS the analyzer host — run agent-host in-place, no SSH


class CredentialMode(StrEnum):
    """Where the target's durable credential lives on the analyzer host."""

    MANAGED_KEY = "managed_key"  # SSH key bootstrapped + stored under ~/.config/scdr/...
    IDENTITY = "identity"  # operator-provided identity file path on the analyzer host
    NONE = "none"  # transport=local — the target is the analyzer host, no credential at all


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
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ScanTarget(StrictModel):
    """A registered scan target (no secret material)."""

    target_id: str
    name: str
    address: str = Field(
        description=(
            "SSH/WinRM endpoint as user@host; "
            "for transport=local a free label (e.g. localhost)"
        )
    )
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
    """Reference to the artifact a finished scan produced (for admin to fetch)."""

    kind: ScanCapability
    report_id: str | None = None  # host  -> GET /reports/asset-reports/{report_id}
    batch_id: str | None = None  # flow  -> the ingested TraceBatch
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
    # Execution mode, derived from capability when absent (so historical rows
    # persisted before this field existed still read back with a correct mode).
    mode: ScanMode | None = None
    state: ScanJobState = ScanJobState.PENDING
    options: ScanJobOptions = Field(default_factory=ScanJobOptions)
    created_at: Timestamp
    started_at: Timestamp | None = None
    finished_at: Timestamp | None = None
    result: ScanResult | None = None
    error: str | None = None

    @model_validator(mode="after")
    def _derive_mode(self) -> ScanJob:
        if self.mode is None:
            self.mode = mode_for_capability(self.capability)
        return self


class TriggerScanRequest(StrictModel):
    """POST /scans body."""

    target_id: str
    capability: ScanCapability
    options: ScanJobOptions = Field(default_factory=ScanJobOptions)


# ----------------------------------------------------- access-credential mgmt
#
# A "credential" here is the *durable* access secret a registered target uses —
# i.e. a tool-managed SSH key on the analyzer host, or an operator-provided
# identity-file path. These are derived (read) from the target registry, not a
# separate store: there is still no plaintext secret persisted by the analyzer.


class CredentialInfo(StrictModel):
    """A durable access credential, summarized for management (no secret material).

    Derived from registered targets: managed keys are grouped by their on-disk
    path (``user@host:port`` deterministic), so ``target_ids`` lists every target
    that shares this credential.
    """

    credential_id: str  # stable id derived from key_path (cred-<hash>)
    credential_mode: CredentialMode  # managed_key | identity (none/local have no credential)
    address: str = Field(description="user@host this credential authenticates to")
    port: int = 22
    key_path: str = Field(description="server-side path of the key on the analyzer host")
    exists: bool = Field(description="whether the key file is present on the analyzer host")
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
