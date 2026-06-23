//! Rust mirror of the kcatta data contract.
//!
//! The authoritative source of these models is the Pydantic package at
//! `analyzer/src/analyzer/schemas/`. The JSON Schema artifacts under
//! `analyzer/schemas-json/` are derived from there, and these Rust types
//! must serialize to JSON that validates against those schemas.
//!
//! Cross-language conformance is enforced by the `agent-host`, `agent-trace`,
//! and guard integration tests against `analyzer/schemas-json/`.
//!
//! # Main types
//!
//! - [`HostInfo`] — one scanned host
//! - [`Asset`] — tagged union of package / service / port / account / credential
//! - [`Vulnerability`] — a finding (e.g. a `kcatta-malware` signature hit)
//! - [`AssetReport`] — full report for one host and one collection cycle (scanner → analyzer)
//! - [`TraceBatch`] — a batch of network trace events with IOC matches (collector → analyzer)
//! - [`GuardEventBatch`] — a batch of real-time protection events + response actions (guard → analyzer)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod trace;
pub use trace::{
    FileOp, FileTraceEvent, IndicatorType, ProcessEventType, ProcessTraceEvent, ThreatMatch,
    TraceBatch, TraceEvent, TraceProto,
};

mod guard;
pub use guard::{
    ActionTaken, FileIntegrityEvent, FimChange, GuardEvent, GuardEventBatch, IdsEvent,
    MalwareEvent, NetworkEvent, Outcome, ProcessEvent,
};

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
    /// Local user account.
    Account(Account),
    /// Credential fingerprint.
    Credential(Credential),
    /// Container workload discovered from static runtime metadata.
    Container(Container),
    /// Container image present in local runtime storage.
    Image(Image),
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

/// One host, one collection cycle: the unit scanner posts to analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetReport {
    /// Unique id for this report instance.
    pub report_id: String,
    /// UTC timestamp when collection finished.
    pub collected_at: DateTime<Utc>,
    /// Version of the scanner that produced this report.
    pub scanner_version: String,
    /// Scanned host descriptor.
    pub host: HostInfo,
    /// Flat list of all asset kinds for this host.
    pub assets: Vec<Asset>,
    /// Findings (malware hits, future rule matches, …).
    pub vulnerabilities: Vec<Vulnerability>,
}
