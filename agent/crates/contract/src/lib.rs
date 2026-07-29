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
    ActionTaken, FileIntegrityEvent, FimChange, GuardEvent, GuardEventBatch, IdsEvent,
    MalwareEvent, NetworkEvent, Outcome, ProcessEvent,
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
