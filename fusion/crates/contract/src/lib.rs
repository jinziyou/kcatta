//! Rust mirror of the posture data contract.
//!
//! The authoritative source of these models is the Pydantic package at
//! `form/src/form/schemas/`. The JSON Schema artifacts under
//! `form/schemas-json/` are derived from there, and these Rust types
//! must serialize to JSON that validates against those schemas.
//!
//! Cross-language conformance is enforced by `fusion-runtime` integration
//! tests against `form/schemas-json/`.
//!
//! # Main types
//!
//! - [`HostInfo`] — one scanned host
//! - [`Asset`] — tagged union of package / service / port / account / credential
//! - [`Vulnerability`] — a finding (e.g. ClamAV signature match)
//! - [`AssetReport`] — full report for one host and one collection cycle (scanner → form)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod flow;
pub use flow::{FlowBatch, FlowEvent, FlowProto, IndicatorType, ThreatMatch};

/// Risk severity aligned with form schema (`info` … `critical`). Shared by the
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
    /// Kind of credential observed.
    pub credential_kind: CredentialKind,
    /// Hash or fingerprint (e.g. `SHA256:…` for SSH keys).
    pub fingerprint: String,
    /// File path where the credential was found.
    pub path: Option<String>,
    /// Owning user when known.
    pub owner: Option<String>,
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
}

/// Security finding attached to an asset or host (ClamAV hit, future rule engines, …).
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
    /// Engine that produced the finding (e.g. `clamav`).
    pub source: String,
    /// Human-readable context (file path, rule detail, …).
    pub evidence: Option<String>,
    /// External reference URLs (CVE pages, advisories, …).
    pub references: Vec<String>,
}

/// One host, one collection cycle: the unit scanner posts to form.
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
