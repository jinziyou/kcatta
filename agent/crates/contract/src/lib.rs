//! Rust contracts for Form-ingest/analyzer-analysis wire data and internal SOC stages.
//!
//! For the wire models, the authoritative source is the Pydantic package at
//! `analyzer/src/analyzer/schemas/`. The JSON Schema artifacts under
//! Form publishes those models under `form/schemas-json/`, and these Rust types must
//! serialize to JSON that validates against the schemas.
//!
//! [`Detection`] is intentionally different: it is a Rust-only internal stage
//! contract passed from detection producers to Respond. It does not implement
//! Serde and is not part of the analyzer Pydantic / JSON Schema wire format.
//!
//! Cross-language conformance is enforced by the `agent-collect-host`, `agent-collect-trace`,
//! and guard integration tests against `form/schemas-json/`.
//!
//! # Main types
//!
//! - [`HostInfo`] — one scanned host
//! - [`Asset`] — tagged union of package / service / port / account / credential
//! - [`Vulnerability`] — a finding (e.g. a `kcatta-malware` signature hit)
//! - [`AssetReport`] — full report for one host and one collection cycle (scanner → analyzer)
//! - [`TraceBatch`] — a batch of network trace events with IOC matches (collector → analyzer)
//! - [`GuardEventBatch`] — a batch of real-time protection events + response actions (guard → analyzer)
//! - [`Detection`] — normalized internal Detect → Respond fact (not a wire model)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod identifier;
pub use identifier::{
    bounded_correlation_id, bounded_wire_text, CORRELATION_IDENTIFIER_MAX_CHARS,
    WIRE_TEXT_MAX_CHARS,
};

mod wire;
use wire::{ensure_chars, ensure_items};
pub use wire::{
    WireContractError, NESTED_LIST_MAX_ITEMS, THREAT_MATCH_MAX_ITEMS, WIRE_LIST_MAX_ITEMS,
    WIRE_STRING_MAX_CHARS,
};

mod trace;
pub use trace::{
    FileOp, FileTraceEvent, IndicatorType, ProcessEventType, ProcessTraceEvent, ThreatMatch,
    TraceBatch, TraceEvent, TraceProto,
};

mod guard;
pub use guard::{
    ActionTaken, AuthenticationEvent, AuthenticationEventType, CollectorHealthEvent,
    CollectorHealthStatus, FileIntegrityEvent, FimChange, GuardEvent, GuardEventBatch, IdsEvent,
    MalwareEvent, NetworkEvent, Outcome, PrivilegeEvent, PrivilegeEventType, PrivilegeMechanism,
    ProcessEvent,
};

mod detection;
pub use detection::Detection;

/// Risk severity aligned with analyzer schema (`info` … `critical`). Shared by the
/// host [`Vulnerability`] findings and the network [`ThreatMatch`] indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding.
    Info,
    /// Low impact.
    Low,
    /// Medium impact.
    Medium,
    /// High impact.
    High,
    /// Critical impact (e.g. active malware).
    Critical,
}

/// Detector identity shared with Analyzer's coverage matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectorKind {
    /// Analyzer-side OSV package matching (not emitted as an Agent run).
    Osv,
    /// Microsoft Defender Antivirus status, scan, and threat telemetry.
    Defender,
    /// Built-in signature malware scan.
    Malware,
    /// Host security-posture rules.
    Posture,
    /// Secret fingerprint scan.
    Secret,
}

/// Producer-observed outcome for one enabled detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectorRunStatus {
    /// The enabled detector finished normally, including a zero-finding pass.
    Complete,
    /// The detector ran but did not cover its full intended scope.
    Partial,
    /// The detector failed; the report may still carry other evidence.
    Failed,
}

/// Explicit detector execution evidence attached to an [`AssetReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorRun {
    /// Detector that was enabled.
    pub detector: DetectorKind,
    /// Producer-observed terminal state.
    pub status: DetectorRunStatus,
    /// Findings carried by this envelope for the detector.
    pub finding_count: usize,
    /// Stable reason when the run is partial or failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Inventory category whose execution state is surfaced to operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionKind {
    /// Host identity and operating-system metadata.
    Host,
    /// Installed packages.
    Package,
    /// Configured/running services.
    Service,
    /// Listening ports.
    Port,
    /// Running processes.
    Process,
    /// Listener ownership enrichment.
    NetworkService,
    /// Mounted filesystems.
    FilesystemMount,
    /// Database instances.
    Database,
    /// Message brokers and queues.
    MessageQueue,
    /// Caches with stateful/network exposure.
    Cache,
    /// Host security controls.
    SecurityControl,
    /// Allowlisted sensitive-file metadata.
    SensitiveFile,
    /// Startup/access persistence entries.
    PersistenceEntry,
    /// Local accounts.
    Account,
    /// Public credential fingerprints.
    Credential,
    /// Container workloads.
    Container,
    /// Local container images.
    Image,
}

/// Producer-observed outcome for one inventory category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectionRunStatus {
    /// The category was fully scanned, including a valid zero result.
    Complete,
    /// The category ran but could not cover all intended sources.
    Partial,
    /// The category failed.
    Failed,
    /// The operator or profile explicitly disabled the category.
    Disabled,
}

/// Explicit inventory execution evidence attached to an [`AssetReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionRun {
    /// Inventory category.
    pub collector: CollectionKind,
    /// Producer-observed terminal state.
    pub status: CollectionRunStatus,
    /// Records found for the complete logical collection cycle.
    pub record_count: usize,
    /// Stable reason when partial, failed, or disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Credential type reported by the scanner (SSH keys, API keys, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// SSH public key fingerprint.
    SshKey,
    /// API key fingerprint or id.
    ApiKey,
    /// Password hash or marker (never plaintext).
    Password,
    /// Bearer or session token fingerprint.
    Token,
}

/// Transport protocol for a listening port asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProto {
    /// TCP listener.
    Tcp,
    /// UDP listener.
    Udp,
}

/// Security-relevant family of a discovered stateful service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataServiceCategory {
    /// Relational, document, graph, or analytical database.
    Database,
    /// Durable broker / streaming / queue service.
    MessageQueue,
    /// Cache that can also expose stateful data or queue semantics.
    Cache,
}

/// Outcome of a metadata-only runtime catalog query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataMetadataStatus {
    /// The query completed, including a valid zero result.
    Complete,
    /// Some metadata was returned but the requested scope was incomplete.
    Partial,
    /// The local database/broker rejected the metadata identity.
    NotAuthorized,
    /// The runtime client or endpoint was unavailable.
    Unavailable,
    /// This engine has no safe connector in the current Agent.
    Unsupported,
}

/// Explicit runtime-catalog coverage attached to a data service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataMetadataCoverage {
    /// Query outcome.
    pub status: DataMetadataStatus,
    /// Metadata rows returned.
    pub record_count: usize,
    /// Stable non-secret reason when not complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Database/broker principal metadata without password material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataPrincipal {
    /// Role/principal name.
    pub name: String,
    /// Whether interactive/session login is allowed.
    pub can_login: Option<bool>,
    /// Whether the principal has a product-level privileged flag.
    pub privileged: Option<bool>,
    /// Whether replication privileges are granted.
    pub replication: Option<bool>,
    /// Direct parent roles/groups.
    pub member_of: Vec<String>,
}

/// Database, topic, or queue metadata without records/messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataObject {
    /// Object name.
    pub name: String,
    /// Normalized type such as database, topic, or queue.
    pub object_type: String,
    /// Owning principal when exposed.
    pub owner: Option<String>,
    /// Whether new access/connections are allowed.
    pub access_enabled: Option<bool>,
    /// Runtime connection limit; negative may represent product-defined unlimited.
    pub connection_limit: Option<i64>,
    /// ACL entry count when available.
    pub acl_entry_count: Option<u64>,
    /// Queue/topic backlog count when available.
    pub backlog_messages: Option<u64>,
    /// Queue/topic retention in seconds when available.
    pub retention_seconds: Option<u64>,
}

/// Host control whose state affects telemetry trust or attack exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityControlType {
    /// Host firewall / packet filter.
    Firewall,
    /// Mandatory access control such as SELinux or AppArmor.
    MandatoryAccessControl,
    /// Host audit subsystem.
    Audit,
    /// Clock synchronization.
    TimeSync,
    /// Remote/system log forwarding.
    LogForwarding,
}

/// Observed control state; configured-only and unknown are not active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityControlStatus {
    /// Runtime evidence proves the control is active.
    Active,
    /// Runtime evidence proves the control is inactive.
    Inactive,
    /// Configuration exists but runtime activity could not be proven.
    Configured,
    /// The control is not installed / exposed on this platform.
    Unavailable,
    /// Evidence was insufficient to decide.
    Unknown,
}

/// Security purpose of a configuration or identity file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveFileCategory {
    /// Account, group, or authentication database metadata.
    Identity,
    /// SSH client/server access configuration.
    Ssh,
    /// Sudo/PAM or another privilege policy.
    Privilege,
    /// Service-manager unit configuration.
    Service,
    /// Cron/at scheduling configuration.
    Scheduler,
    /// Database or broker configuration.
    Database,
    /// Other allowlisted application configuration.
    Application,
}

/// Mechanism capable of starting code automatically or granting access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceType {
    /// A systemd service unit.
    SystemdService,
    /// A systemd timer unit.
    SystemdTimer,
    /// A cron entry.
    Cron,
    /// An at job.
    AtJob,
    /// A login shell profile.
    ShellProfile,
    /// A configured kernel module load.
    KernelModule,
    /// An SSH authorized-key file.
    AuthorizedKey,
    /// A container restart policy.
    ContainerRestart,
}

/// Host identity and environment as observed during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// Stable id for this host within one scan root (derived from hostname + root).
    pub host_id: String,
    /// Value from `etc/hostname` or equivalent.
    pub hostname: String,
    /// Human-readable OS string from `os-release` or similar.
    pub os: String,
    /// Kernel version string when available.
    pub kernel: Option<String>,
    /// CPU architecture when detectable.
    pub arch: Option<String>,
    /// Observed IP addresses (may be empty in static v0 scans).
    pub ip_addrs: Vec<String>,
    /// Observed MAC addresses (may be empty in static v0 scans).
    pub mac_addrs: Vec<String>,
    /// Last boot time when available.
    pub boot_time: Option<DateTime<Utc>>,
}

impl HostInfo {
    /// Normalize ordinary text and validate nested address limits for Form.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        self.host_id = bounded_correlation_id(&self.host_id);
        self.hostname = bounded_wire_text(&self.hostname);
        self.os = bounded_wire_text(&self.os);
        if let Some(kernel) = &mut self.kernel {
            *kernel = bounded_wire_text(kernel);
        }
        if let Some(arch) = &mut self.arch {
            *arch = bounded_wire_text(arch);
        }
        ensure_items("host.ip_addrs", self.ip_addrs.len(), NESTED_LIST_MAX_ITEMS)?;
        ensure_items(
            "host.mac_addrs",
            self.mac_addrs.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        for address in &mut self.ip_addrs {
            *address = bounded_correlation_id(address);
        }
        for address in &mut self.mac_addrs {
            *address = bounded_correlation_id(address);
        }
        Ok(())
    }
}

/// Installed software package (OS or language ecosystem).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// Unique id for this package asset on the host.
    pub asset_id: String,
    /// Parent asset id when this row came from a nested (container rootfs) scan.
    pub parent_asset_id: Option<String>,
    /// Package name.
    pub name: String,
    /// Installed version string.
    pub version: String,
    /// Collector that produced this row (e.g. `dpkg`, `npm`).
    pub source: Option<String>,
    /// Source package name when exposed by the package manager.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// Source package version used to build this binary package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
    /// Install path on disk when known.
    pub install_path: Option<String>,
    /// OSV ecosystem for vulnerability matching, e.g. `Debian:12`, `PyPI`.
    pub ecosystem: Option<String>,
}

/// Long-running service (systemd unit, SysV init script, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Unique id for this service asset on the host.
    pub asset_id: String,
    /// Parent asset id when this row came from a nested (container rootfs) scan.
    pub parent_asset_id: Option<String>,
    /// Service or unit name.
    pub name: String,
    /// Runtime status (e.g. `enabled`, `disabled`, `active`).
    pub status: String,
    /// Path to the main executable when known.
    pub exec_path: Option<String>,
}

/// Network listener (reserved for future live scans; not populated by v0 static asset scan).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    /// Unique id for this port asset on the host.
    pub asset_id: String,
    /// Parent asset id when this row came from a nested (container rootfs) scan.
    pub parent_asset_id: Option<String>,
    /// Transport protocol.
    pub proto: PortProto,
    /// Port number.
    pub port: u16,
    /// Bind address (e.g. `0.0.0.0`, `::`).
    pub listen_addr: String,
    /// Name of the listening process when known.
    pub process_name: Option<String>,
    /// PID of the listening process when known.
    pub pid: Option<u32>,
}

/// Running process observed from a live host's process filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAsset {
    /// Stable process asset id for this collection cycle.
    pub asset_id: String,
    /// Parent asset id when collected inside a container root.
    pub parent_asset_id: Option<String>,
    /// Process id.
    pub pid: u32,
    /// Parent process id when readable.
    pub ppid: Option<u32>,
    /// Kernel/process name.
    pub name: String,
    /// Resolved executable path when readable.
    pub exe_path: Option<String>,
    /// SHA-256 of the executable when it was safely readable within limits.
    pub executable_sha256: Option<String>,
    /// Effective user id when readable.
    pub uid: Option<u32>,
    /// Username resolved from the scan root's account database.
    pub username: Option<String>,
    /// Redacted display command line; raw credentials are never serialized.
    pub command_line: Option<String>,
    /// Whether one or more command-line values were replaced.
    pub command_line_redacted: bool,
    /// Owning systemd unit when exposed by cgroup metadata.
    pub systemd_unit: Option<String>,
    /// Container id inferred from cgroup metadata.
    pub container_id: Option<String>,
    /// Process start time when it can be safely mapped to UTC.
    pub started_at: Option<DateTime<Utc>>,
}

/// Listener enriched with process, service, package and workload ownership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkService {
    /// Stable network-service asset id.
    pub asset_id: String,
    /// Parent asset id when applicable.
    pub parent_asset_id: Option<String>,
    /// Transport protocol.
    pub proto: PortProto,
    /// Listening port.
    pub port: u16,
    /// Bind address.
    pub listen_addr: String,
    /// Referenced basic port asset.
    pub port_asset_id: String,
    /// Referenced process asset when ownership was readable.
    pub process_asset_id: Option<String>,
    /// Referenced service asset when a systemd unit could be mapped.
    pub service_asset_id: Option<String>,
    /// Process name when readable.
    pub process_name: Option<String>,
    /// Executable path when readable.
    pub exe_path: Option<String>,
    /// Executable SHA-256 when available.
    pub executable_sha256: Option<String>,
    /// Effective uid when readable.
    pub uid: Option<u32>,
    /// Username when resolvable.
    pub username: Option<String>,
    /// Owning systemd unit.
    pub systemd_unit: Option<String>,
    /// Owning container id.
    pub container_id: Option<String>,
    /// Installed package mapped to the executable when known.
    pub package_name: Option<String>,
}

/// Mounted filesystem with security-relevant options and capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemMount {
    /// Stable mount asset id.
    pub asset_id: String,
    /// Parent asset id when applicable.
    pub parent_asset_id: Option<String>,
    /// Kernel-reported mount source.
    pub source: String,
    /// Mount point path.
    pub mount_point: String,
    /// Filesystem type.
    pub fs_type: String,
    /// Normalized mount options.
    pub options: Vec<String>,
    /// Total bytes when statvfs succeeded.
    pub total_bytes: Option<u64>,
    /// Bytes available to an unprivileged process when statvfs succeeded.
    pub available_bytes: Option<u64>,
    /// Total inodes when exposed by the filesystem.
    pub total_inodes: Option<u64>,
    /// Available inodes when exposed by the filesystem.
    pub available_inodes: Option<u64>,
    /// Whether the mount is read-only.
    pub readonly: bool,
    /// Whether the source/type represents a remote filesystem.
    pub remote: bool,
}

/// Database, message broker, or cache metadata discovered without reading data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataService {
    /// Stable data-service asset id.
    pub asset_id: String,
    /// Parent asset id when applicable.
    pub parent_asset_id: Option<String>,
    /// Stateful service family.
    pub category: DataServiceCategory,
    /// Normalized engine name.
    pub engine: String,
    /// Product version when available from package/static metadata.
    pub version: Option<String>,
    /// Referenced process asset.
    pub process_asset_id: Option<String>,
    /// Referenced enriched listener assets.
    pub network_service_ids: Vec<String>,
    /// Non-secret endpoints (address/port or socket path).
    pub endpoints: Vec<String>,
    /// Configuration paths only; raw config is not embedded.
    pub config_paths: Vec<String>,
    /// Data directory paths only; records are never read.
    pub data_paths: Vec<String>,
    /// TLS state; `None` means unknown.
    pub tls_enabled: Option<bool>,
    /// Authentication state; `None` means unknown.
    pub authentication_enabled: Option<bool>,
    /// Anonymous-access state; `None` means unknown.
    pub anonymous_access: Option<bool>,
    /// Audit state; `None` means unknown.
    pub audit_enabled: Option<bool>,
    /// Replication/cluster state; `None` means unknown.
    pub replication_enabled: Option<bool>,
    /// Backup state; `None` means unknown.
    pub backup_enabled: Option<bool>,
    /// Runtime role/principal metadata; never contains password hashes.
    pub principals: Vec<DataPrincipal>,
    /// Explicit principal-query outcome.
    pub principal_coverage: DataMetadataCoverage,
    /// Runtime database/topic/queue metadata; never contains records/messages.
    pub objects: Vec<DataObject>,
    /// Explicit object-query outcome.
    pub object_coverage: DataMetadataCoverage,
    /// Non-secret discovery evidence source.
    pub discovery_source: String,
}

/// Firewall, MAC, audit, clock, or log-forwarding posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityControl {
    /// Stable control asset id.
    pub asset_id: String,
    /// Parent asset id when applicable.
    pub parent_asset_id: Option<String>,
    /// Control family.
    pub control: SecurityControlType,
    /// Product/subsystem name.
    pub name: String,
    /// Observed state.
    pub status: SecurityControlStatus,
    /// Optional normalized mode.
    pub mode: Option<String>,
    /// Bounded, non-secret summary.
    pub details: Option<String>,
}

/// Metadata and digest for an allowlisted security-sensitive regular file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveFile {
    /// Stable asset id derived from the path.
    pub asset_id: String,
    /// Parent asset id when applicable.
    pub parent_asset_id: Option<String>,
    /// Absolute display path inside the scanned root.
    pub path: String,
    /// Security purpose of the file.
    pub category: SensitiveFileCategory,
    /// Unix owner uid when exposed.
    pub owner_uid: Option<u32>,
    /// Unix owner gid when exposed.
    pub owner_gid: Option<u32>,
    /// Unix permission/special bits when exposed.
    pub mode: Option<u32>,
    /// File length.
    pub size_bytes: Option<u64>,
    /// Last modification time.
    pub modified_at: Option<DateTime<Utc>>,
    /// SHA-256 for a bounded regular file; never the raw content.
    pub sha256: Option<String>,
    /// Whether the file is writable by everyone.
    pub world_writable: bool,
    /// Whether the file is group-writable.
    pub group_writable: bool,
    /// Whether the setuid bit is present.
    pub setuid: bool,
    /// Whether the setgid bit is present.
    pub setgid: bool,
    /// Proven unsafe ACL state, or unknown when ACL inspection is unavailable.
    pub acl_risk: Option<bool>,
}

/// Metadata-only persistence entry with a redacted command summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    /// Stable asset id derived from mechanism and source.
    pub asset_id: String,
    /// Parent asset id when applicable.
    pub parent_asset_id: Option<String>,
    /// Persistence mechanism.
    pub entry_type: PersistenceType,
    /// Unit, file, module, or entry name.
    pub name: String,
    /// File containing the entry.
    pub source_path: String,
    /// User or service principal when known.
    pub principal: Option<String>,
    /// Redacted command summary.
    pub command: Option<String>,
    /// Whether one or more command values were replaced.
    pub command_redacted: bool,
    /// Enabled state when it can be proven.
    pub enabled: Option<bool>,
    /// Digest of the bounded source file.
    pub content_sha256: Option<String>,
    /// Source-file modification time.
    pub modified_at: Option<DateTime<Utc>>,
    /// Bounded normalized risk labels.
    pub risk_flags: Vec<String>,
}

/// Local user account from `/etc/passwd` or equivalent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Unique id for this account asset on the host.
    pub asset_id: String,
    /// Parent asset id when this row came from a nested (container rootfs) scan.
    pub parent_asset_id: Option<String>,
    /// Login name.
    pub username: String,
    /// Numeric user id.
    pub uid: Option<i64>,
    /// Login shell path.
    pub shell: Option<String>,
    /// Last login timestamp when available.
    pub last_login: Option<DateTime<Utc>>,
}

/// Credential fingerprint (e.g. SSH public key); never includes secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Unique id for this credential asset on the host.
    pub asset_id: String,
    /// Parent asset id when this row came from a nested (container rootfs) scan.
    pub parent_asset_id: Option<String>,
    /// Kind of credential observed.
    pub credential_kind: CredentialKind,
    /// Hash or fingerprint (e.g. `SHA256:…` for SSH keys).
    pub fingerprint: String,
    /// File path where the credential was found.
    pub path: Option<String>,
    /// Owning user when known.
    pub owner: Option<String>,
}

/// Container workload discovered from static runtime metadata
/// (Docker / Podman / containerd / Kubernetes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    /// Unique id for this container asset on the host.
    pub asset_id: String,
    /// Parent container `asset_id` when this row came from a nested rootfs scan.
    pub parent_asset_id: Option<String>,
    /// Container name (normalized, no leading slash).
    pub name: String,
    /// Container runtime: `docker` | `podman` | `containerd` | `kubernetes`.
    pub runtime: String,
    /// Image reference when known from static metadata.
    pub image: Option<String>,
    /// Last known state, e.g. `running` / `exited` / `created`.
    pub status: Option<String>,
    /// Runtime container id when available.
    pub container_id: Option<String>,
    /// Path to the static metadata file under `scan_root`.
    pub config_path: Option<String>,
    /// Merged container rootfs path under `scan_root` when resolved statically.
    pub rootfs_path: Option<String>,
}

/// Container image present in local runtime storage (pulled image, which may
/// never have been run as a container), discovered from static on-disk metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image {
    /// Unique id for this image asset on the host (e.g. `img-docker-<shortid>`).
    pub asset_id: String,
    /// Parent asset `asset_id` when applicable (None for top-level images).
    pub parent_asset_id: Option<String>,
    /// Primary image reference (e.g. `nginx:1.25`), or the short image id when untagged.
    pub name: String,
    /// Image store / runtime: `docker` | `podman`.
    pub runtime: String,
    /// Content-addressable image id when known (e.g. `sha256:...`).
    pub image_id: Option<String>,
    /// All repository tags / names pointing at this image.
    pub tags: Vec<String>,
    /// Image creation time from the image config, when cheaply available.
    pub created: Option<String>,
}

/// Endpoint security product and the protection state observed on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProduct {
    /// Stable id for this product on the host.
    pub asset_id: String,
    /// Parent asset id when applicable (normally `None` for host protection).
    pub parent_asset_id: Option<String>,
    /// Product name, for example `Microsoft Defender Antivirus`.
    pub name: String,
    /// Product vendor.
    pub vendor: String,
    /// Normalized state: `active`, `passive`, `disabled`, or `unavailable`.
    pub status: String,
    /// Vendor-specific running mode.
    pub mode: Option<String>,
    /// Installed product/platform version.
    pub product_version: Option<String>,
    /// Antimalware engine version.
    pub engine_version: Option<String>,
    /// Security-intelligence/signature version.
    pub signature_version: Option<String>,
    /// Last successful security-intelligence update.
    pub signature_updated_at: Option<DateTime<Utc>>,
    /// Whether the product reports security intelligence as stale.
    pub signatures_out_of_date: Option<bool>,
    /// Whether real-time protection is enabled.
    pub real_time_protection: Option<bool>,
    /// Whether behavior monitoring is enabled.
    pub behavior_monitor: Option<bool>,
    /// Whether downloaded files and attachments are inspected.
    pub ioav_protection: Option<bool>,
    /// Whether tamper protection is enabled.
    pub tamper_protection: Option<bool>,
    /// Whether cloud-delivered protection is enabled.
    pub cloud_protection: Option<bool>,
    /// End time of the last quick scan.
    pub last_quick_scan_at: Option<DateTime<Utc>>,
    /// End time of the last full scan.
    pub last_full_scan_at: Option<DateTime<Utc>>,
}

/// Tagged union of all asset types reported by the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Asset {
    /// Installed package.
    Package(Package),
    /// Installed or configured service.
    Service(Service),
    /// Network listener.
    Port(Port),
    /// Running process.
    Process(ProcessAsset),
    /// Listener enriched with runtime ownership.
    NetworkService(NetworkService),
    /// Mounted filesystem.
    FilesystemMount(FilesystemMount),
    /// Database, broker, or cache.
    DataService(DataService),
    /// Host security-control posture.
    SecurityControl(SecurityControl),
    /// Security-sensitive file metadata/digest.
    SensitiveFile(SensitiveFile),
    /// Startup/access persistence entry.
    PersistenceEntry(PersistenceEntry),
    /// Local user account.
    Account(Account),
    /// Credential fingerprint.
    Credential(Credential),
    /// Container workload discovered from static runtime metadata.
    Container(Container),
    /// Container image present in local runtime storage.
    Image(Image),
    /// Endpoint protection product and its observed health.
    SecurityProduct(SecurityProduct),
}

impl Asset {
    /// Normalize ordinary asset text and reject unrepresentable nested lists.
    ///
    /// Dedicated asset ids and path fields are validated, never shortened.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        match self {
            Asset::Package(asset) => asset.normalize_wire_fields(),
            Asset::Service(asset) => asset.normalize_wire_fields(),
            Asset::Port(asset) => asset.normalize_wire_fields(),
            Asset::Process(asset) => asset.normalize_wire_fields(),
            Asset::NetworkService(asset) => asset.normalize_wire_fields(),
            Asset::FilesystemMount(asset) => asset.normalize_wire_fields(),
            Asset::DataService(asset) => asset.normalize_wire_fields(),
            Asset::SecurityControl(asset) => asset.normalize_wire_fields(),
            Asset::SensitiveFile(asset) => asset.normalize_wire_fields(),
            Asset::PersistenceEntry(asset) => asset.normalize_wire_fields(),
            Asset::Account(asset) => asset.normalize_wire_fields(),
            Asset::Credential(asset) => asset.normalize_wire_fields(),
            Asset::Container(asset) => asset.normalize_wire_fields(),
            Asset::Image(asset) => asset.normalize_wire_fields(),
            Asset::SecurityProduct(asset) => asset.normalize_wire_fields(),
        }
    }
}

impl Package {
    /// Normalize a package row for a static or merged wire artifact.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.name = bounded_wire_text(&self.name);
        self.version = bounded_wire_text(&self.version);
        bound_optional_text(&mut self.source);
        bound_optional_text(&mut self.source_name);
        bound_optional_text(&mut self.source_version);
        validate_optional_identifier("package.install_path", self.install_path.as_deref())?;
        bound_optional_text(&mut self.ecosystem);
        Ok(())
    }
}

impl Service {
    /// Normalize a service row for a static or merged wire artifact.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.name = bounded_wire_text(&self.name);
        self.status = bounded_wire_text(&self.status);
        validate_optional_identifier("service.exec_path", self.exec_path.as_deref())
    }
}

impl Port {
    /// Normalize a port row for a static or merged wire artifact.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.listen_addr = bounded_wire_text(&self.listen_addr);
        bound_optional_text(&mut self.process_name);
        Ok(())
    }
}

impl ProcessAsset {
    /// Normalize a process row while preserving only producer-redacted command text.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.name = bounded_wire_text(&self.name);
        validate_optional_identifier("process.exe_path", self.exe_path.as_deref())?;
        bound_optional_text(&mut self.executable_sha256);
        bound_optional_text(&mut self.username);
        bound_optional_text(&mut self.command_line);
        bound_optional_text(&mut self.systemd_unit);
        bound_optional_text(&mut self.container_id);
        Ok(())
    }
}

impl NetworkService {
    /// Normalize listener ownership fields and validate cross-asset references.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        ensure_chars(
            "network_service.port_asset_id",
            &self.port_asset_id,
            WIRE_STRING_MAX_CHARS,
        )?;
        validate_optional_identifier(
            "network_service.process_asset_id",
            self.process_asset_id.as_deref(),
        )?;
        validate_optional_identifier(
            "network_service.service_asset_id",
            self.service_asset_id.as_deref(),
        )?;
        self.listen_addr = bounded_wire_text(&self.listen_addr);
        bound_optional_text(&mut self.process_name);
        validate_optional_identifier("network_service.exe_path", self.exe_path.as_deref())?;
        bound_optional_text(&mut self.executable_sha256);
        bound_optional_text(&mut self.username);
        bound_optional_text(&mut self.systemd_unit);
        bound_optional_text(&mut self.container_id);
        bound_optional_text(&mut self.package_name);
        Ok(())
    }
}

impl FilesystemMount {
    /// Normalize a mount row and bound its option list.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        validate_optional_identifier("filesystem_mount.source", Some(&self.source))?;
        validate_optional_identifier("filesystem_mount.mount_point", Some(&self.mount_point))?;
        self.fs_type = bounded_wire_text(&self.fs_type);
        ensure_items(
            "filesystem_mount.options",
            self.options.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        for option in &mut self.options {
            *option = bounded_wire_text(option);
        }
        Ok(())
    }
}

impl DataService {
    /// Normalize non-secret data-service metadata and bound all path/reference lists.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.engine = bounded_wire_text(&self.engine);
        bound_optional_text(&mut self.version);
        validate_optional_identifier(
            "data_service.process_asset_id",
            self.process_asset_id.as_deref(),
        )?;
        ensure_items(
            "data_service.network_service_ids",
            self.network_service_ids.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        ensure_items(
            "data_service.endpoints",
            self.endpoints.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        ensure_items(
            "data_service.config_paths",
            self.config_paths.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        ensure_items(
            "data_service.data_paths",
            self.data_paths.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        for reference in &self.network_service_ids {
            ensure_chars(
                "data_service.network_service_id",
                reference,
                WIRE_STRING_MAX_CHARS,
            )?;
        }
        for endpoint in &mut self.endpoints {
            *endpoint = bounded_wire_text(endpoint);
        }
        for path in &self.config_paths {
            ensure_chars("data_service.config_path", path, WIRE_STRING_MAX_CHARS)?;
        }
        for path in &self.data_paths {
            ensure_chars("data_service.data_path", path, WIRE_STRING_MAX_CHARS)?;
        }
        ensure_items(
            "data_service.principals",
            self.principals.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        for principal in &mut self.principals {
            principal.name = bounded_wire_text(&principal.name);
            ensure_items(
                "data_service.principal.member_of",
                principal.member_of.len(),
                NESTED_LIST_MAX_ITEMS,
            )?;
            for role in &mut principal.member_of {
                *role = bounded_wire_text(role);
            }
        }
        if let Some(reason) = &mut self.principal_coverage.reason {
            *reason = bounded_wire_text(reason);
        }
        ensure_items(
            "data_service.objects",
            self.objects.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        for object in &mut self.objects {
            object.name = bounded_wire_text(&object.name);
            object.object_type = bounded_wire_text(&object.object_type);
            bound_optional_text(&mut object.owner);
        }
        if let Some(reason) = &mut self.object_coverage.reason {
            *reason = bounded_wire_text(reason);
        }
        self.discovery_source = bounded_wire_text(&self.discovery_source);
        Ok(())
    }
}

impl SecurityControl {
    /// Normalize control display metadata.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.name = bounded_wire_text(&self.name);
        bound_optional_text(&mut self.mode);
        bound_optional_text(&mut self.details);
        Ok(())
    }
}

impl SensitiveFile {
    /// Validate paths and normalize the digest without serializing file contents.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        validate_optional_identifier("sensitive_file.path", Some(&self.path))?;
        bound_optional_text(&mut self.sha256);
        Ok(())
    }
}

impl PersistenceEntry {
    /// Normalize display fields while preserving validated source paths.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.name = bounded_wire_text(&self.name);
        validate_optional_identifier("persistence_entry.source_path", Some(&self.source_path))?;
        bound_optional_text(&mut self.principal);
        bound_optional_text(&mut self.command);
        bound_optional_text(&mut self.content_sha256);
        ensure_items(
            "persistence_entry.risk_flags",
            self.risk_flags.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        for flag in &mut self.risk_flags {
            *flag = bounded_wire_text(flag);
        }
        Ok(())
    }
}

impl Account {
    /// Normalize an account row for a static or merged wire artifact.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.username = bounded_wire_text(&self.username);
        validate_optional_identifier("account.shell", self.shell.as_deref())
    }
}

impl Credential {
    /// Normalize a credential row for a static or merged wire artifact.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.fingerprint = bounded_wire_text(&self.fingerprint);
        validate_optional_identifier("credential.path", self.path.as_deref())?;
        bound_optional_text(&mut self.owner);
        Ok(())
    }
}

impl Container {
    /// Normalize a container row for a merged wire artifact.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.name = bounded_wire_text(&self.name);
        self.runtime = bounded_wire_text(&self.runtime);
        bound_optional_text(&mut self.image);
        bound_optional_text(&mut self.status);
        bound_optional_text(&mut self.container_id);
        validate_optional_identifier("container.config_path", self.config_path.as_deref())?;
        validate_optional_identifier("container.rootfs_path", self.rootfs_path.as_deref())
    }
}

impl Image {
    /// Normalize an image row and reject a tag list the schema cannot represent.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        ensure_items("image.tags", self.tags.len(), NESTED_LIST_MAX_ITEMS)?;
        self.name = bounded_wire_text(&self.name);
        self.runtime = bounded_wire_text(&self.runtime);
        bound_optional_text(&mut self.image_id);
        bound_optional_text(&mut self.created);
        for tag in &mut self.tags {
            *tag = bounded_wire_text(tag);
        }
        Ok(())
    }
}

impl SecurityProduct {
    /// Normalize security-product text while preserving explicit protection flags.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        validate_asset_ids(&self.asset_id, self.parent_asset_id.as_deref())?;
        self.name = bounded_wire_text(&self.name);
        self.vendor = bounded_wire_text(&self.vendor);
        self.status = bounded_wire_text(&self.status);
        bound_optional_text(&mut self.mode);
        bound_optional_text(&mut self.product_version);
        bound_optional_text(&mut self.engine_version);
        bound_optional_text(&mut self.signature_version);
        Ok(())
    }
}

fn bound_optional_text(value: &mut Option<String>) {
    if let Some(value) = value {
        *value = bounded_wire_text(value);
    }
}

fn validate_asset_ids(
    asset_id: &str,
    parent_asset_id: Option<&str>,
) -> Result<(), WireContractError> {
    ensure_chars("asset.asset_id", asset_id, WIRE_STRING_MAX_CHARS)?;
    validate_optional_identifier("asset.parent_asset_id", parent_asset_id)
}

fn validate_optional_identifier(field: &str, value: Option<&str>) -> Result<(), WireContractError> {
    if let Some(value) = value {
        ensure_chars(field, value, WIRE_STRING_MAX_CHARS)?;
    }
    Ok(())
}

/// Security finding attached to an asset or host (`kcatta-malware` hit, future rule engines, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Signature id, CVE id, or rule name depending on `source`.
    pub vuln_id: String,
    /// Normalized severity.
    pub severity: Severity,
    /// CVSS base score when known.
    pub cvss_score: Option<f64>,
    /// `host_id` or asset id this finding relates to.
    pub affected_asset_id: String,
    /// Owning image/container asset id when the affected package came from a
    /// nested image/container scan; lets findings be grouped per image. `None`
    /// for host-level findings. (Manual mirror of the analyzer schema field.)
    pub parent_asset_id: Option<String>,
    /// Engine that produced the finding (e.g. `kcatta-malware`, the built-in signature scanner).
    pub source: String,
    /// Human-readable context (file path, rule detail, …).
    pub evidence: Option<String>,
    /// External reference URLs (CVE pages, advisories, …).
    pub references: Vec<String>,
}

impl Vulnerability {
    /// Bound fields represented by Form `CorrelationIdentifier` values.
    ///
    /// Asset references and evidence are intentionally left untouched because
    /// they use the wider wire/path contracts.
    pub fn bound_correlation_ids(&mut self) {
        self.vuln_id = bounded_correlation_id(&self.vuln_id);
        self.source = bounded_correlation_id(&self.source);
    }

    /// Bound ordinary descriptive strings without changing asset references.
    pub fn bound_wire_text_fields(&mut self) {
        if let Some(evidence) = &mut self.evidence {
            *evidence = bounded_wire_text(evidence);
        }
    }

    /// Normalize this finding and validate references/asset identifiers.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        self.bound_correlation_ids();
        self.bound_wire_text_fields();
        ensure_chars(
            "vulnerability.affected_asset_id",
            &self.affected_asset_id,
            WIRE_STRING_MAX_CHARS,
        )?;
        validate_optional_identifier(
            "vulnerability.parent_asset_id",
            self.parent_asset_id.as_deref(),
        )?;
        ensure_items(
            "vulnerability.references",
            self.references.len(),
            NESTED_LIST_MAX_ITEMS,
        )?;
        for reference in &self.references {
            ensure_chars("vulnerability.reference", reference, WIRE_STRING_MAX_CHARS)?;
        }
        Ok(())
    }
}

/// One host, one collection cycle: agentd posts it to Form for analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetReport {
    /// Unique id for this report instance.
    pub report_id: String,
    /// UTC timestamp when collection finished.
    pub collected_at: DateTime<Utc>,
    /// Version of the scanner that produced this report.
    pub scanner_version: String,
    /// Authenticated Agent identity injected by Form. Agent-originated payloads
    /// leave this absent; Form must never trust a value supplied by the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_agent_id: Option<String>,
    /// Form-owned registered target attribution. Agent producers leave it
    /// absent; Form binds both mTLS uploads and pulled scan artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_target_id: Option<String>,
    /// Scanned host descriptor.
    pub host: HostInfo,
    /// Flat list of all asset kinds for this host.
    pub assets: Vec<Asset>,
    /// Findings (malware hits, future rule matches, …).
    pub vulnerabilities: Vec<Vulnerability>,
    /// Explicit detector runs. `None` is a legacy/unknown producer; `Some([])`
    /// proves that the producer enabled none of the Agent detectors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_runs: Option<Vec<DetectorRun>>,
    /// Explicit collection runs. `None` is a legacy/unknown producer; a
    /// complete run with zero records proves that the category was scanned and
    /// no matching assets were found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_runs: Option<Vec<CollectionRun>>,
}

impl AssetReport {
    /// Bound every Form `CorrelationIdentifier` carried by this report.
    ///
    /// In particular this does not shorten any asset id, affected asset id,
    /// filesystem path, or evidence value.
    pub fn bound_correlation_ids(&mut self) {
        self.report_id = bounded_correlation_id(&self.report_id);
        self.scanner_version = bounded_correlation_id(&self.scanner_version);
        if let Some(source_agent_id) = &mut self.source_agent_id {
            *source_agent_id = bounded_correlation_id(source_agent_id);
        }
        if let Some(source_target_id) = &mut self.source_target_id {
            *source_target_id = bounded_correlation_id(source_target_id);
        }
        self.host.host_id = bounded_correlation_id(&self.host.host_id);
        for address in &mut self.host.ip_addrs {
            *address = bounded_correlation_id(address);
        }
        for address in &mut self.host.mac_addrs {
            *address = bounded_correlation_id(address);
        }
        for vulnerability in &mut self.vulnerabilities {
            vulnerability.bound_correlation_ids();
        }
    }

    /// Bound ordinary descriptive strings while preserving paths and asset ids.
    pub fn bound_wire_text_fields(&mut self) {
        for vulnerability in &mut self.vulnerabilities {
            vulnerability.bound_wire_text_fields();
        }
    }

    /// Normalize all fields that can be represented in one AssetReport item.
    ///
    /// Top-level asset/finding counts are intentionally not rejected here:
    /// agentd losslessly splits those streams before upload.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        self.report_id = bounded_correlation_id(&self.report_id);
        self.scanner_version = bounded_correlation_id(&self.scanner_version);
        if let Some(source_agent_id) = &mut self.source_agent_id {
            *source_agent_id = bounded_correlation_id(source_agent_id);
        }
        if let Some(source_target_id) = &mut self.source_target_id {
            *source_target_id = bounded_correlation_id(source_target_id);
        }
        self.host.normalize_wire_fields()?;
        for asset in &mut self.assets {
            asset.normalize_wire_fields()?;
        }
        for vulnerability in &mut self.vulnerabilities {
            vulnerability.normalize_wire_fields()?;
        }
        if let Some(runs) = &mut self.detector_runs {
            ensure_items("asset_report.detector_runs", runs.len(), 32)?;
            for run in runs {
                if let Some(reason) = &mut run.reason {
                    *reason = bounded_wire_text(reason);
                }
            }
        }
        if let Some(runs) = &mut self.collection_runs {
            ensure_items("asset_report.collection_runs", runs.len(), 64)?;
            for run in runs {
                if let Some(reason) = &mut run.reason {
                    *reason = bounded_wire_text(reason);
                }
            }
        }
        Ok(())
    }

    /// Validate top-level list limits for a single-file/static envelope.
    pub fn validate_envelope_list_bounds(&self) -> Result<(), WireContractError> {
        ensure_items(
            "asset_report.assets",
            self.assets.len(),
            WIRE_LIST_MAX_ITEMS,
        )?;
        ensure_items(
            "asset_report.vulnerabilities",
            self.vulnerabilities.len(),
            WIRE_LIST_MAX_ITEMS,
        )
    }
}
