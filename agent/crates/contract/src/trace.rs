//! Network flow contract — the `agent-trace` (network collector) envelope.
//!
//! Mirrors `analyzer.schemas.trace` / `analyzer.schemas.threat`. These types live here
//! alongside the host [`AssetReport`](crate::AssetReport) contract so a single
//! crate is the Rust mirror of `analyzer/schemas-json/` and the `agentd` umbrella's
//! built-in ingest can serialize both host and network telemetry.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Severity;

/// Transport / application protocol class of an observed trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceProto {
    /// TCP flow.
    Tcp,
    /// UDP flow.
    Udp,
    /// ICMP flow.
    Icmp,
    /// Any other / unclassified protocol.
    Other,
}

/// Kind of IOC an indicator represents. Mirrors
/// `analyzer.schemas.threat.IndicatorType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorType {
    /// IP address indicator (matched against flow `src_ip` / `dst_ip`).
    Ip,
    /// Domain indicator (matched against `dns_query` / `tls_sni`, parent-domain aware).
    Domain,
    /// JA3 TLS fingerprint indicator (matched against `ja3`).
    Ja3,
}

/// One IOC hit observed on a flow by agent-trace's preliminary processing.
/// Mirrors `analyzer.schemas.threat.ThreatMatch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatMatch {
    /// The matched indicator value (the IP, domain, or JA3 hash).
    pub indicator: String,
    /// Which kind of indicator matched.
    pub indicator_type: IndicatorType,
    /// Free-text category from the feed (e.g. `c2`, `malware`, `phishing`).
    pub category: String,
    /// Severity carried by the matching indicator.
    pub severity: Severity,
    /// Feed / source that supplied the indicator.
    pub source: String,
    /// Optional human-readable context for the match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A single observed network trace (5-tuple aggregate) with optional
/// application-layer metadata and any IOC matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Stable id for this flow within the batch.
    pub trace_id: String,
    /// Host / sensor id that observed the flow.
    pub host_id: String,

    /// First-seen timestamp for the flow.
    pub start_ts: DateTime<Utc>,
    /// Last-seen timestamp for the flow.
    pub end_ts: DateTime<Utc>,

    /// Protocol class.
    pub proto: TraceProto,
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Source port (absent for ICMP).
    pub src_port: Option<u16>,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Destination port (absent for ICMP).
    pub dst_port: Option<u16>,

    /// Bytes sent from source to destination.
    pub bytes_sent: u64,
    /// Bytes received from destination to source.
    pub bytes_recv: u64,
    /// Packets sent from source to destination.
    pub packets_sent: u64,
    /// Packets received from destination to source.
    pub packets_recv: u64,

    /// Detected application protocol (e.g. `SSH`) when known.
    pub app_proto: Option<String>,
    /// DNS query name when the flow carried one.
    pub dns_query: Option<String>,
    /// TLS SNI server name when present in a ClientHello.
    pub tls_sni: Option<String>,
    /// JA3 TLS fingerprint when computed.
    pub ja3: Option<String>,

    /// IOC matches found by agent-trace's preliminary processing.
    /// Serialized as `[]` when empty so the field is always present.
    #[serde(default)]
    pub threat_intel: Vec<ThreatMatch>,
}

/// agent-trace -> analyzer: a batch of trace events from one collector instance.
///
/// Carries three homogeneous streams from one eBPF collection cycle: network
/// traces (5-tuple flows), file operations, and process lifecycle events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBatch {
    /// Unique id for this batch instance.
    pub batch_id: String,
    /// UTC timestamp when the batch was assembled.
    pub collected_at: DateTime<Utc>,
    /// Id of the collector instance that produced the batch.
    pub collector_id: String,
    /// Version string of the collector that produced the batch.
    pub collector_version: String,
    /// Network traces (5-tuple flows + IOC matches).
    pub events: Vec<TraceEvent>,
    /// File-system operations observed by the eBPF tracer.
    #[serde(default)]
    pub file_events: Vec<FileTraceEvent>,
    /// Process exec/exit events observed by the eBPF tracer.
    #[serde(default)]
    pub process_events: Vec<ProcessTraceEvent>,
}

/// File-system operation kind observed by the eBPF tracer. Mirrors the
/// `op` literal of `analyzer.schemas.trace.FileTraceEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileOp {
    /// `open()` of an existing path.
    Open,
    /// File creation (`O_CREAT`, `creat`, `mknod`).
    Create,
    /// Write to a file.
    Write,
    /// `unlink()` / delete.
    Unlink,
    /// `rename()` (see `target_path`).
    Rename,
    /// Permission change (`chmod`).
    Chmod,
    /// Hard link (see `target_path`).
    Link,
    /// Symbolic link (see `target_path`).
    Symlink,
    /// Directory creation.
    Mkdir,
}

/// A single file-system operation observed by the eBPF tracer.
/// Mirrors `analyzer.schemas.trace.FileTraceEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTraceEvent {
    /// Stable id for this event within the batch.
    pub trace_id: String,
    /// Host / sensor id that observed the operation.
    pub host_id: String,
    /// When the operation occurred.
    pub ts: DateTime<Utc>,
    /// PID of the process performing the operation.
    pub pid: u32,
    /// Short process name (kernel `TASK_COMM`, <=16 bytes).
    pub comm: String,
    /// Acting user id when known.
    pub uid: Option<u32>,
    /// The file operation.
    pub op: FileOp,
    /// Primary target path of the operation.
    pub path: String,
    /// Second path for link / rename operations.
    pub target_path: Option<String>,
    /// Syscall return value (fd or `-errno`) when captured.
    pub ret: Option<i64>,
    /// IOC matches (known-bad path / hash) from collector-side processing.
    #[serde(default)]
    pub threat_intel: Vec<ThreatMatch>,
}

/// Process lifecycle event kind. Mirrors the `event_type` literal of
/// `analyzer.schemas.trace.ProcessTraceEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessEventType {
    /// Program invocation (`execve`).
    Exec,
    /// Process exit.
    Exit,
}

/// A process lifecycle event observed by the eBPF tracer.
/// Mirrors `analyzer.schemas.trace.ProcessTraceEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTraceEvent {
    /// Stable id for this event within the batch.
    pub trace_id: String,
    /// Host / sensor id that observed the event.
    pub host_id: String,
    /// When the event occurred.
    pub ts: DateTime<Utc>,
    /// Whether this is an `exec` or `exit` event.
    pub event_type: ProcessEventType,
    /// PID of the process.
    pub pid: u32,
    /// Parent PID when known.
    pub ppid: Option<u32>,
    /// Acting user id when known.
    pub uid: Option<u32>,
    /// Short process name (kernel `TASK_COMM`, <=16 bytes).
    pub comm: String,
    /// Resolved executable path for exec events.
    pub exe: Option<String>,
    /// Command-line arguments for exec events.
    #[serde(default)]
    pub argv: Vec<String>,
    /// cgroup / container id for workload attribution.
    pub cgroup: Option<String>,
    /// Exit code for exit events.
    pub exit_code: Option<i32>,
    /// IOC matches (known-bad binary hash / name) from collector-side processing.
    #[serde(default)]
    pub threat_intel: Vec<ThreatMatch>,
}
