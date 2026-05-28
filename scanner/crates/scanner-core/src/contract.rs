//! Rust mirror of the cyber-posture data contract.
//!
//! The authoritative source of these models is the Pydantic package at
//! `form/src/form/schemas/`. The JSON Schema artifacts under
//! `form/schemas-json/` are derived from there, and these Rust types
//! must serialize to JSON that validates against those schemas.
//!
//! Cross-language conformance is enforced by
//! `scanner-core/tests/contract.rs`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    SshKey,
    ApiKey,
    Password,
    Token,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub host_id: String,
    pub hostname: String,
    pub os: String,
    pub kernel: Option<String>,
    pub arch: Option<String>,
    pub ip_addrs: Vec<String>,
    pub mac_addrs: Vec<String>,
    pub boot_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub asset_id: String,
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub install_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub asset_id: String,
    pub name: String,
    pub status: String,
    pub exec_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub asset_id: String,
    pub proto: PortProto,
    pub port: u16,
    pub listen_addr: String,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub asset_id: String,
    pub username: String,
    pub uid: Option<i64>,
    pub shell: Option<String>,
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub asset_id: String,
    pub credential_kind: CredentialKind,
    pub fingerprint: String,
    pub path: Option<String>,
    pub owner: Option<String>,
}

/// Tagged union of all asset types reported by the scanner.
///
/// The `kind` discriminator is emitted by serde during serialization and
/// matches the `kind: Literal[...]` discriminator on the Python side.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Asset {
    Package(Package),
    Service(Service),
    Port(Port),
    Account(Account),
    Credential(Credential),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub vuln_id: String,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub affected_asset_id: String,
    pub source: String,
    pub evidence: Option<String>,
    pub references: Vec<String>,
}

/// scanner -> form: one host, one collection cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetReport {
    pub report_id: String,
    pub collected_at: DateTime<Utc>,
    pub scanner_version: String,
    pub host: HostInfo,
    pub assets: Vec<Asset>,
    pub vulnerabilities: Vec<Vulnerability>,
}
