//! Network flow contract — the `agent-collect-trace` (network collector) envelope.
//!
//! Mirrors `analyzer.schemas.trace` / `analyzer.schemas.threat`. These types live here
//! alongside the host [`AssetReport`](crate::AssetReport) contract so a single
//! crate is the Rust mirror of `form/schemas-json/` and the `agentd` umbrella's
//! built-in ingest can serialize both host and network telemetry.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::wire::{ensure_chars, ensure_items};
use crate::{
    bounded_correlation_id, bounded_wire_text, Severity, WireContractError, NESTED_LIST_MAX_ITEMS,
    THREAT_MATCH_MAX_ITEMS, WIRE_LIST_MAX_ITEMS, WIRE_STRING_MAX_CHARS,
};

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

/// One IOC hit observed on a flow by agent-collect-trace's preliminary processing.
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

impl ThreatMatch {
    /// Bound the Form correlation fields while preserving descriptive context.
    pub fn bound_correlation_ids(&mut self) {
        self.indicator = bounded_correlation_id(&self.indicator);
        self.category = bounded_correlation_id(&self.category);
        self.source = bounded_correlation_id(&self.source);
    }

    /// Bound optional descriptive text without changing trace/path fields.
    pub fn bound_wire_text_fields(&mut self) {
        if let Some(description) = &mut self.description {
            *description = bounded_wire_text(description);
        }
    }

    /// Normalize all bounded threat-match strings.
    pub fn normalize_wire_fields(&mut self) {
        self.bound_correlation_ids();
        self.bound_wire_text_fields();
    }
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

    /// IOC matches found by agent-collect-trace's preliminary processing.
    /// Serialized as `[]` when empty so the field is always present.
    #[serde(default)]
    pub threat_intel: Vec<ThreatMatch>,
}

impl TraceEvent {
    fn normalize_wire_fields(&mut self) {
        self.trace_id = bounded_correlation_id(&self.trace_id);
        self.host_id = bounded_correlation_id(&self.host_id);
        bound_optional_text(&mut self.app_proto);
        bound_optional_text(&mut self.dns_query);
        bound_optional_text(&mut self.tls_sni);
        bound_optional_text(&mut self.ja3);
        for threat_match in &mut self.threat_intel {
            threat_match.normalize_wire_fields();
        }
    }

    fn validate_nested_wire_bounds(&self) -> Result<(), WireContractError> {
        validate_threat_matches("trace_event.threat_intel", &self.threat_intel)
    }
}

/// agent-collect-trace -> Form -> analyzer: trace events from one collector instance.
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
    /// Authenticated Agent identity injected by Form. Agent-originated payloads
    /// leave this absent; Form must never trust a value supplied by the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_agent_id: Option<String>,
    /// Form-owned registered target attribution. Agent producers leave it
    /// absent; Form binds both mTLS uploads and pulled scan artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_target_id: Option<String>,
    /// Network traces (5-tuple flows + IOC matches).
    pub events: Vec<TraceEvent>,
    /// File-system operations observed by the eBPF tracer.
    #[serde(default)]
    pub file_events: Vec<FileTraceEvent>,
    /// Process exec/exit events observed by the eBPF tracer.
    #[serde(default)]
    pub process_events: Vec<ProcessTraceEvent>,
}

impl TraceBatch {
    /// Bound every Form `CorrelationIdentifier` carried by this batch.
    ///
    /// Paths, command lines, cgroups, DNS/SNI values, and other wider wire
    /// values are deliberately not shortened.
    pub fn bound_correlation_ids(&mut self) {
        self.batch_id = bounded_correlation_id(&self.batch_id);
        self.collector_id = bounded_correlation_id(&self.collector_id);
        self.collector_version = bounded_correlation_id(&self.collector_version);
        if let Some(source_agent_id) = &mut self.source_agent_id {
            *source_agent_id = bounded_correlation_id(source_agent_id);
        }
        if let Some(source_target_id) = &mut self.source_target_id {
            *source_target_id = bounded_correlation_id(source_target_id);
        }

        for event in &mut self.events {
            event.trace_id = bounded_correlation_id(&event.trace_id);
            event.host_id = bounded_correlation_id(&event.host_id);
            for threat_match in &mut event.threat_intel {
                threat_match.bound_correlation_ids();
            }
        }
        for event in &mut self.file_events {
            event.trace_id = bounded_correlation_id(&event.trace_id);
            event.host_id = bounded_correlation_id(&event.host_id);
            event.comm = bounded_correlation_id(&event.comm);
            for threat_match in &mut event.threat_intel {
                threat_match.bound_correlation_ids();
            }
        }
        for event in &mut self.process_events {
            event.trace_id = bounded_correlation_id(&event.trace_id);
            event.host_id = bounded_correlation_id(&event.host_id);
            event.comm = bounded_correlation_id(&event.comm);
            for threat_match in &mut event.threat_intel {
                threat_match.bound_correlation_ids();
            }
        }
    }

    /// Bound ordinary threat descriptions without changing paths or commands.
    pub fn bound_wire_text_fields(&mut self) {
        for event in &mut self.events {
            for threat_match in &mut event.threat_intel {
                threat_match.bound_wire_text_fields();
            }
        }
        for event in &mut self.file_events {
            for threat_match in &mut event.threat_intel {
                threat_match.bound_wire_text_fields();
            }
        }
        for event in &mut self.process_events {
            for threat_match in &mut event.threat_intel {
                threat_match.bound_wire_text_fields();
            }
        }
    }

    /// Normalize strings and validate dedicated path fields.
    ///
    /// Stream and nested-list counts remain separate so agentd can losslessly
    /// split them before upload.
    pub fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        self.batch_id = bounded_correlation_id(&self.batch_id);
        self.collector_id = bounded_correlation_id(&self.collector_id);
        self.collector_version = bounded_correlation_id(&self.collector_version);
        if let Some(source_agent_id) = &mut self.source_agent_id {
            *source_agent_id = bounded_correlation_id(source_agent_id);
        }
        if let Some(source_target_id) = &mut self.source_target_id {
            *source_target_id = bounded_correlation_id(source_target_id);
        }
        for event in &mut self.events {
            event.normalize_wire_fields();
        }
        for event in &mut self.file_events {
            event.normalize_wire_fields()?;
        }
        for event in &mut self.process_events {
            event.normalize_wire_fields()?;
        }
        Ok(())
    }

    /// Validate nested arrays (`threat_intel`, process `argv`) without checking
    /// the three top-level streams.
    pub fn validate_nested_wire_bounds(&self) -> Result<(), WireContractError> {
        for event in &self.events {
            event.validate_nested_wire_bounds()?;
        }
        for event in &self.file_events {
            event.validate_nested_wire_bounds()?;
        }
        for event in &self.process_events {
            event.validate_nested_wire_bounds()?;
        }
        Ok(())
    }

    /// Validate every list bound for a single-file/static TraceBatch.
    pub fn validate_envelope_list_bounds(&self) -> Result<(), WireContractError> {
        ensure_items("trace_batch.events", self.events.len(), WIRE_LIST_MAX_ITEMS)?;
        ensure_items(
            "trace_batch.file_events",
            self.file_events.len(),
            WIRE_LIST_MAX_ITEMS,
        )?;
        ensure_items(
            "trace_batch.process_events",
            self.process_events.len(),
            WIRE_LIST_MAX_ITEMS,
        )?;
        self.validate_nested_wire_bounds()
    }
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

impl FileTraceEvent {
    fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        self.trace_id = bounded_correlation_id(&self.trace_id);
        self.host_id = bounded_correlation_id(&self.host_id);
        self.comm = bounded_correlation_id(&self.comm);
        ensure_chars("file_trace.path", &self.path, WIRE_STRING_MAX_CHARS)?;
        if let Some(target_path) = &self.target_path {
            ensure_chars("file_trace.target_path", target_path, WIRE_STRING_MAX_CHARS)?;
        }
        for threat_match in &mut self.threat_intel {
            threat_match.normalize_wire_fields();
        }
        Ok(())
    }

    fn validate_nested_wire_bounds(&self) -> Result<(), WireContractError> {
        validate_threat_matches("file_trace.threat_intel", &self.threat_intel)
    }
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

impl ProcessTraceEvent {
    fn normalize_wire_fields(&mut self) -> Result<(), WireContractError> {
        self.trace_id = bounded_correlation_id(&self.trace_id);
        self.host_id = bounded_correlation_id(&self.host_id);
        self.comm = bounded_correlation_id(&self.comm);
        if let Some(exe) = &self.exe {
            ensure_chars("process_trace.exe", exe, WIRE_STRING_MAX_CHARS)?;
        }
        for argument in &mut self.argv {
            *argument = bounded_wire_text(argument);
        }
        bound_optional_text(&mut self.cgroup);
        for threat_match in &mut self.threat_intel {
            threat_match.normalize_wire_fields();
        }
        Ok(())
    }

    fn validate_nested_wire_bounds(&self) -> Result<(), WireContractError> {
        ensure_items("process_trace.argv", self.argv.len(), NESTED_LIST_MAX_ITEMS)?;
        validate_threat_matches("process_trace.threat_intel", &self.threat_intel)
    }
}

fn bound_optional_text(value: &mut Option<String>) {
    if let Some(value) = value {
        *value = bounded_wire_text(value);
    }
}

fn validate_threat_matches(field: &str, matches: &[ThreatMatch]) -> Result<(), WireContractError> {
    ensure_items(field, matches.len(), THREAT_MATCH_MAX_ITEMS)
}
