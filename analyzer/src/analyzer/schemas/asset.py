"""Asset findings reported by scanner.

`Asset` is a discriminated union keyed on `kind`. Adding a new asset
type means: (1) create a new `_AssetBase` subclass with a unique
`kind: Literal["..."]`, (2) add it to the `Asset` union, (3) bump the
contract version.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field

from .common import MAX_NESTED_LIST_ITEMS, StrictModel, Timestamp, WireIdentifier


class CredentialKind(StrEnum):
    """Kind of credential material discovered on a host."""

    SSH_KEY = "ssh_key"
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"


class _AssetBase(StrictModel):
    asset_id: WireIdentifier = Field(description="Stable identifier assigned by the scanner")
    parent_asset_id: WireIdentifier | None = Field(
        default=None,
        description="Parent asset_id when this row came from a nested (container rootfs) scan",
    )


class Package(_AssetBase):
    """An installed software package detected on the host."""

    kind: Literal["package"] = "package"
    name: str
    version: str
    source: str | None = Field(
        default=None,
        description="Package manager, e.g. apt / yum / pip / npm",
    )
    source_name: str | None = Field(
        default=None,
        description="Source package name when the package manager exposes it",
    )
    source_version: str | None = Field(
        default=None,
        description="Source package version used to build the installed binary package",
    )
    install_path: str | None = None
    ecosystem: str | None = Field(
        default=None,
        description=(
            "OSV ecosystem for vulnerability matching, e.g. 'Debian:12', "
            "'PyPI', 'npm'. When unset, detection falls back to the host's "
            "ecosystem derived from host.os."
        ),
    )


class Service(_AssetBase):
    """A system service (daemon) and its current run state."""

    kind: Literal["service"] = "service"
    name: str
    status: str = Field(description="running / stopped / failed / ...")
    exec_path: str | None = None


class Port(_AssetBase):
    """A listening network port and the process bound to it."""

    kind: Literal["port"] = "port"
    proto: Literal["tcp", "udp"]
    port: int = Field(ge=0, le=65535)
    listen_addr: str
    process_name: str | None = None
    pid: int | None = Field(default=None, ge=0)


class ProcessAsset(_AssetBase):
    """A running process observed on a live host.

    ``command_line`` is a producer-redacted display value.  Producers must not
    send raw environment variables, passwords, tokens, connection strings, or
    other secret-bearing arguments.
    """

    kind: Literal["process"] = "process"
    pid: int = Field(ge=0)
    ppid: int | None = Field(default=None, ge=0)
    name: str
    exe_path: str | None = None
    executable_sha256: str | None = None
    uid: int | None = Field(default=None, ge=0)
    username: str | None = None
    command_line: str | None = Field(
        default=None,
        description="Redacted command line; never contains raw credential arguments",
    )
    command_line_redacted: bool = Field(
        default=False,
        description="True when one or more command-line values were replaced",
    )
    systemd_unit: str | None = None
    container_id: str | None = None
    started_at: Timestamp | None = None


class NetworkService(_AssetBase):
    """A listener enriched with process, service and workload ownership."""

    kind: Literal["network_service"] = "network_service"
    proto: Literal["tcp", "udp"]
    port: int = Field(ge=0, le=65535)
    listen_addr: str
    port_asset_id: WireIdentifier
    process_asset_id: WireIdentifier | None = None
    service_asset_id: WireIdentifier | None = None
    process_name: str | None = None
    exe_path: str | None = None
    executable_sha256: str | None = None
    uid: int | None = Field(default=None, ge=0)
    username: str | None = None
    systemd_unit: str | None = None
    container_id: str | None = None
    package_name: str | None = None


class FilesystemMount(_AssetBase):
    """A mounted filesystem and its security-relevant capacity/options."""

    kind: Literal["filesystem_mount"] = "filesystem_mount"
    source: str
    mount_point: str
    fs_type: str
    options: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)
    total_bytes: int | None = Field(default=None, ge=0)
    available_bytes: int | None = Field(default=None, ge=0)
    total_inodes: int | None = Field(default=None, ge=0)
    available_inodes: int | None = Field(default=None, ge=0)
    readonly: bool
    remote: bool


class DataServiceCategory(StrEnum):
    """Security-relevant stateful service family."""

    DATABASE = "database"
    MESSAGE_QUEUE = "message_queue"
    CACHE = "cache"


class DataMetadataStatus(StrEnum):
    """Outcome of a metadata-only runtime catalog query."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    NOT_AUTHORIZED = "not_authorized"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"


class DataMetadataCoverage(StrictModel):
    """Explicit catalog coverage; a complete zero is distinct from no access."""

    status: DataMetadataStatus
    record_count: int = Field(default=0, ge=0)
    reason: str | None = None


class DataPrincipal(StrictModel):
    """Database/broker principal metadata without password material."""

    name: str
    can_login: bool | None = None
    privileged: bool | None = None
    replication: bool | None = None
    member_of: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)


class DataObject(StrictModel):
    """Database/topic/queue metadata; records and messages are never included."""

    name: str
    object_type: str
    owner: str | None = None
    access_enabled: bool | None = None
    connection_limit: int | None = None
    acl_entry_count: int | None = Field(default=None, ge=0)
    backlog_messages: int | None = Field(default=None, ge=0)
    retention_seconds: int | None = Field(default=None, ge=0)


class DataService(_AssetBase):
    """A database, message broker, or cache discovered without reading data."""

    kind: Literal["data_service"] = "data_service"
    category: DataServiceCategory
    engine: str
    version: str | None = None
    process_asset_id: WireIdentifier | None = None
    network_service_ids: list[WireIdentifier] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    endpoints: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)
    config_paths: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)
    data_paths: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)
    tls_enabled: bool | None = None
    authentication_enabled: bool | None = None
    anonymous_access: bool | None = None
    audit_enabled: bool | None = None
    replication_enabled: bool | None = None
    backup_enabled: bool | None = None
    principals: list[DataPrincipal] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    principal_coverage: DataMetadataCoverage = Field(
        default_factory=lambda: DataMetadataCoverage(
            status=DataMetadataStatus.UNSUPPORTED,
            reason="runtime_principal_metadata_not_supported",
        )
    )
    objects: list[DataObject] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)
    object_coverage: DataMetadataCoverage = Field(
        default_factory=lambda: DataMetadataCoverage(
            status=DataMetadataStatus.UNSUPPORTED,
            reason="runtime_object_metadata_not_supported",
        )
    )
    discovery_source: str = Field(
        description="Non-secret evidence source, e.g. process, package, config, or listener"
    )


class SecurityControlType(StrEnum):
    """Host control whose state affects collection trust or exposure."""

    FIREWALL = "firewall"
    MAC = "mandatory_access_control"
    AUDIT = "audit"
    TIME_SYNC = "time_sync"
    LOG_FORWARDING = "log_forwarding"


class SecurityControlStatus(StrEnum):
    """Observed state without upgrading unknown/config-only evidence to active."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    CONFIGURED = "configured"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class SecurityControl(_AssetBase):
    """Firewall, MAC, audit, time-sync, or log-forwarding posture."""

    kind: Literal["security_control"] = "security_control"
    control: SecurityControlType
    name: str
    status: SecurityControlStatus
    mode: str | None = None
    details: str | None = Field(
        default=None,
        description="Bounded non-secret summary; raw configuration is never embedded",
    )


class SensitiveFileCategory(StrEnum):
    """Security purpose of a configuration or identity file."""

    IDENTITY = "identity"
    SSH = "ssh"
    PRIVILEGE = "privilege"
    SERVICE = "service"
    SCHEDULER = "scheduler"
    DATABASE = "database"
    APPLICATION = "application"


class SensitiveFile(_AssetBase):
    """Metadata and digest for a security-sensitive file.

    File contents, ACL entries, password hashes and configuration values are
    intentionally absent from this contract.
    """

    kind: Literal["sensitive_file"] = "sensitive_file"
    path: str
    category: SensitiveFileCategory
    owner_uid: int | None = Field(default=None, ge=0)
    owner_gid: int | None = Field(default=None, ge=0)
    mode: int | None = Field(default=None, ge=0, le=0o7777)
    size_bytes: int | None = Field(default=None, ge=0)
    modified_at: Timestamp | None = None
    sha256: str | None = Field(
        default=None,
        description="Digest of bounded regular-file bytes; raw contents are never transmitted",
    )
    world_writable: bool
    group_writable: bool
    setuid: bool
    setgid: bool
    acl_risk: bool | None = Field(
        default=None,
        description="True only when an unsafe ACL is proven; None means ACL state was unavailable",
    )


class PersistenceType(StrEnum):
    """Mechanism capable of starting code automatically or granting access."""

    SYSTEMD_SERVICE = "systemd_service"
    SYSTEMD_TIMER = "systemd_timer"
    CRON = "cron"
    AT_JOB = "at_job"
    SHELL_PROFILE = "shell_profile"
    KERNEL_MODULE = "kernel_module"
    AUTHORIZED_KEY = "authorized_key"
    CONTAINER_RESTART = "container_restart"


class PersistenceEntry(_AssetBase):
    """Metadata-only persistence entry with a redacted command summary."""

    kind: Literal["persistence_entry"] = "persistence_entry"
    entry_type: PersistenceType
    name: str
    source_path: str
    principal: str | None = None
    command: str | None = Field(
        default=None,
        description="Redacted command summary; never raw credentials or configuration values",
    )
    command_redacted: bool = False
    enabled: bool | None = None
    content_sha256: str | None = None
    modified_at: Timestamp | None = None
    risk_flags: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)


class Account(_AssetBase):
    """A local user account present on the host."""

    kind: Literal["account"] = "account"
    username: str
    uid: int | None = None
    shell: str | None = None
    last_login: Timestamp | None = None


class Credential(_AssetBase):
    """A credential artifact found on the host, referenced only by its public fingerprint."""

    kind: Literal["credential"] = "credential"
    credential_kind: CredentialKind
    fingerprint: str = Field(
        description="Public fingerprint or hash; the secret itself MUST NEVER be transmitted",
    )
    path: str | None = None
    owner: str | None = None


class Container(_AssetBase):
    """A container workload discovered from static runtime metadata."""

    kind: Literal["container"] = "container"
    name: str
    runtime: str = Field(
        description="Container runtime, e.g. docker / podman / containerd / kubernetes",
    )
    image: str | None = Field(
        default=None, description="Image reference when known from static metadata"
    )
    status: str | None = Field(
        default=None, description="Last known state, e.g. running / exited / created"
    )
    container_id: str | None = Field(
        default=None, description="Runtime container id when available"
    )
    config_path: str | None = Field(
        default=None, description="Path to the static metadata file under scan_root"
    )
    rootfs_path: str | None = Field(
        default=None,
        description="Merged container rootfs path under scan_root when resolved statically",
    )


class Image(_AssetBase):
    """A container image present in local runtime storage (a pulled image that
    may never have run), discovered from static on-disk metadata."""

    kind: Literal["image"] = "image"
    name: str = Field(
        description="Primary image reference (e.g. nginx:1.25), or short image id when untagged"
    )
    runtime: str = Field(description="Image store / runtime, e.g. docker / podman")
    image_id: str | None = Field(
        default=None, description="Content-addressable image id (e.g. sha256:...)"
    )
    tags: list[str] = Field(
        default_factory=list,
        max_length=MAX_NESTED_LIST_ITEMS,
        description="All repository tags / names for this image",
    )
    created: str | None = Field(
        default=None, description="Image creation time from the image config, when available"
    )


class SecurityProduct(_AssetBase):
    """Endpoint security product and the protection state observed on a host."""

    kind: Literal["security_product"] = "security_product"
    name: str
    vendor: str
    status: Literal["active", "passive", "disabled", "unavailable"]
    mode: str | None = Field(
        default=None,
        description="Vendor-specific running mode, for example Normal or Passive Mode",
    )
    product_version: str | None = None
    engine_version: str | None = None
    signature_version: str | None = None
    signature_updated_at: Timestamp | None = None
    signatures_out_of_date: bool | None = None
    real_time_protection: bool | None = None
    behavior_monitor: bool | None = None
    ioav_protection: bool | None = None
    tamper_protection: bool | None = None
    cloud_protection: bool | None = None
    last_quick_scan_at: Timestamp | None = None
    last_full_scan_at: Timestamp | None = None


Asset = Annotated[
    Package
    | Service
    | Port
    | ProcessAsset
    | NetworkService
    | FilesystemMount
    | DataService
    | SecurityControl
    | SensitiveFile
    | PersistenceEntry
    | Account
    | Credential
    | Container
    | Image
    | SecurityProduct,
    Field(discriminator="kind"),
]
